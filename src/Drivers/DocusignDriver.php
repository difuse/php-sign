<?php

namespace Helori\PhpSign\Drivers;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use Helori\PhpSign\Elements\Document;
use Helori\PhpSign\Elements\DocumentResult;
use Helori\PhpSign\Elements\Scenario;
use Helori\PhpSign\Elements\Signer;
use Helori\PhpSign\Elements\SignerResult;
use Helori\PhpSign\Elements\Transaction;
use Helori\PhpSign\Elements\Webhook;
use Helori\PhpSign\Exceptions\DriverAuthException;
use Helori\PhpSign\Exceptions\NotFoundException;
use Helori\PhpSign\Exceptions\SignException;
use Helori\PhpSign\Exceptions\ValidationException;
use Helori\PhpSign\Utilities\DateParser;
use libphonenumber\NumberParseException;
use libphonenumber\PhoneNumberUtil;
use Psr\Http\Message\ResponseInterface;
use Psr\SimpleCache\CacheInterface;


/**
 * Docusign eSignature REST API v2.1, embedded signing.
 *
 * Docusign sends no email: the application sends each signer to the signing
 * page with createSigningUrl(), which returns a URL valid 5 minutes and only
 * once. Ask for it right before redirecting the signer, never store it.
 *
 * Each signer confirms with a code sent to their phone (Docusign "Phone
 * Authentication"), so every signer needs a phone number.
 *
 * Docusign flags apps that poll an envelope's status more than once every 15
 * minutes. Set a webhook URL on the scenario (Connect) and keep polling as a
 * slow fallback.
 *
 * Config keys:
 * - mode: "production" or anything else for the demo environment
 * - integrator_key, user_id: the integration key and the user it impersonates
 * - private_key: the RSA private key (PEM) paired with the integration key
 * - account_id: optional, the user's default account otherwise
 * - redirect_uri: optional, a redirect URI of the integration key, used to build the consent URL
 * - cache: optional PSR-16 cache for the access token, the account and the phone workflow
 * - client: optional Guzzle client
 * - phone_workflow_id: optional, read from the account otherwise
 * - phone_region: region of phone numbers written without country code, "FR" by default
 * - page_height: page height in PDF points, A4 (841) by default
 * - expiration_days: 14 by default
 * - view_authentication_method: how the application identified the signer before
 *   opening the signing page, printed on the certificate, "Email" by default
 */
class DocusignDriver implements DriverInterface, SupportsSigningUrl, SupportsCertificate
{
    const DEFAULT_PAGE_HEIGHT = 841;

    const PHONE_AUTHENTICATION_WORKFLOW = 'Phone Authentication';

    const WEBHOOK_EVENTS = [
        'envelope-sent',
        'envelope-delivered',
        'envelope-completed',
        'envelope-declined',
        'envelope-voided',
        'recipient-sent',
        'recipient-delivered',
        'recipient-completed',
        'recipient-declined',
        'recipient-authenticationfailed',
    ];

    const VOIDED_REASON = 'Canceled by the sender';

    // Docusign only keeps the signer's full name. Splitting it back at the
    // first space breaks compound first names, so both parts travel in the
    // recipient's custom fields.
    const FIRSTNAME_FIELD = 'firstname:';
    const LASTNAME_FIELD = 'lastname:';

    // Height of the mention line written above the signature, in points
    const MENTION_LINE_HEIGHT = 12;

    const TOKEN_LIFETIME_SECONDS = 3600;
    const TOKEN_RENEWAL_MARGIN_SECONDS = 300;
    const ACCOUNT_CACHE_SECONDS = 86400;

    /**
     * @var array
     */
    protected $config;

    /**
     * The OAuth host, without scheme
     *
     * @var string
     */
    protected $authHost;

    /**
     * @var \GuzzleHttp\ClientInterface
     */
    protected $client;

    /**
     * @var \Psr\SimpleCache\CacheInterface|null
     */
    protected $cache;

    /**
     * @var string|null
     */
    protected $accessToken;

    /**
     * @var array|null ['account_id' => string, 'base_uri' => string]
     */
    protected $account;

    /**
     * @var string|null
     */
    protected $phoneWorkflowId;

    /**
     * Create a new DocusignDriver instance. Makes no API call: authentication
     * happens on the first request.
     *
     * @return void
     */
    public function __construct(array $config)
    {
        foreach(['mode', 'integrator_key', 'user_id', 'private_key'] as $key){
            if(!isset($config[$key]) || $config[$key] === ''){
                throw new ValidationException('Docusign config parameter "'.$key.'" must be set');
            }
        }

        $client = $config['client'] ?? null;
        if(!is_null($client) && !$client instanceof ClientInterface){
            throw new ValidationException('Docusign config parameter "client" must be a Guzzle client');
        }

        $cache = $config['cache'] ?? null;
        if(!is_null($cache) && !$cache instanceof CacheInterface){
            throw new ValidationException('Docusign config parameter "cache" must be a PSR-16 cache');
        }

        $this->config = $config;
        $this->authHost = $config['mode'] === 'production' ? 'account.docusign.com' : 'account-d.docusign.com';
        $this->client = $client ?? new Client(['timeout' => 60, 'connect_timeout' => 10]);
        $this->cache = $cache;
    }

    /**
     * Get the driver's name
     *
     * @return string
     */
    public function getName()
    {
        return 'docusign';
    }

    /**
     * Get the driver's specific expiration days
     *
     * @return int
     */
    public function getExpirationDays()
    {
        return (int) ($this->option('expiration_days') ?? 14);
    }

    /**
     * The URL the impersonated user opens once to let the integration act on
     * their behalf. Null when no redirect URI is configured.
     *
     * @return string|null
     */
    public function getConsentUrl()
    {
        $redirectUri = $this->option('redirect_uri');

        if(is_null($redirectUri)){
            return null;
        }

        return 'https://'.$this->authHost.'/oauth/auth?'.http_build_query([
            'response_type' => 'code',
            'scope' => 'signature impersonation',
            'client_id' => $this->config['integrator_key'],
            'redirect_uri' => $redirectUri,
        ]);
    }

    /**
     * Create a transaction from a scenario
     *
     * @param  \Helori\PhpSign\Elements\Scenario  $scenario
     * @return \Helori\PhpSign\Elements\Transaction
     */
    public function createTransaction(Scenario $scenario)
    {
        $envelope = $this->api('POST', '/envelopes', ['json' => $this->envelopeDefinition($scenario)]);

        return $this->getTransaction($envelope['envelopeId']);
    }

    /**
     * Get transaction
     *
     * @param  string  $transactionId
     * @return \Helori\PhpSign\Elements\Transaction
     */
    public function getTransaction(string $transactionId)
    {
        return $this->transactionFrom($this->envelope($transactionId));
    }

    /**
     * Get the signed documents. The certificate of completion is left out:
     * see getCertificate().
     *
     * @param  string  $transactionId
     * @return array<\Helori\PhpSign\Elements\DocumentResult>
     */
    public function getDocuments(string $transactionId)
    {
        $envelopePath = '/envelopes/'.rawurlencode($transactionId);
        $list = $this->api('GET', $envelopePath.'/documents');
        $documents = [];

        foreach($list['envelopeDocuments'] ?? [] as $envelopeDocument){

            $documentId = (string) ($envelopeDocument['documentId'] ?? '');

            if($documentId === '' || $documentId === 'certificate' || ($envelopeDocument['type'] ?? 'content') !== 'content'){
                continue;
            }

            $documentPath = $envelopePath.'/documents/'.rawurlencode($documentId);
            $fields = $this->api('GET', $documentPath.'/fields');

            $metadata = [];
            foreach($fields['documentFields'] ?? [] as $field){
                if(isset($field['name'])){
                    $metadata[$field['name']] = $field['value'] ?? null;
                }
            }

            $document = new DocumentResult();
            $document->setId((int) $documentId);
            $document->setName($envelopeDocument['name'] ?? null);
            $document->setContent($this->download($documentPath));
            $document->setMetadata($metadata);

            $documents[] = $document;
        }

        return $documents;
    }

    /**
     * Get the certificate of completion
     *
     * @param  string  $transactionId
     * @return string
     */
    public function getCertificate(string $transactionId): string
    {
        return $this->download('/envelopes/'.rawurlencode($transactionId).'/documents/certificate');
    }

    /**
     * Void the envelope. Its documents are kept for the audit trail.
     *
     * @param  string  $transactionId
     * @return \Helori\PhpSign\Elements\Transaction
     */
    public function cancelTransaction(string $transactionId)
    {
        $this->api('PUT', '/envelopes/'.rawurlencode($transactionId), ['json' => [
            'status' => 'voided',
            'voidedReason' => self::VOIDED_REASON,
        ]]);

        return $this->getTransaction($transactionId);
    }

    /**
     * Create a URL that opens the signing page of one signer. Valid 5 minutes,
     * once.
     *
     * @param  string  $transactionId
     * @param  int  $signerId
     * @param  string|null  $returnUrl
     * @return string
     */
    public function createSigningUrl(string $transactionId, int $signerId, ?string $returnUrl = null): string
    {
        $envelope = $this->envelope($transactionId);
        $recipient = null;

        foreach($envelope['recipients']['signers'] ?? [] as $signer){
            if((int) ($signer['recipientId'] ?? 0) === $signerId){
                $recipient = $signer;
            }
        }

        if(is_null($recipient)){
            throw new NotFoundException('Signer "'.$signerId.'" is not a recipient of the Docusign envelope "'.$transactionId.'"');
        }

        if(empty($recipient['clientUserId'])){
            throw new ValidationException('Signer "'.$signerId.'" is not an embedded recipient: Docusign signs them by email');
        }

        $returnUrl = $returnUrl ?: ($this->textCustomFields($envelope)['returnUrl'] ?? null);

        if(empty($returnUrl)){
            throw new ValidationException('No return URL for the Docusign signing page: pass one, the scenario had none');
        }

        $view = $this->api('POST', '/envelopes/'.rawurlencode($transactionId).'/views/recipient', ['json' => [
            'returnUrl' => $returnUrl,
            'authenticationMethod' => $this->option('view_authentication_method') ?? 'Email',
            'clientUserId' => $recipient['clientUserId'],
            'recipientId' => (string) $recipient['recipientId'],
            'userName' => $recipient['name'],
            'email' => $recipient['email'],
        ]]);

        if(empty($view['url'])){
            throw new SignException('Docusign returned no signing URL for signer "'.$signerId.'"');
        }

        return $view['url'];
    }

    /**
     * Convert a Connect (JSON SIM) webhook into the common webhook data format.
     * Check the request's signature with isValidWebhookSignature() first.
     *
     * @param  array  $requestData
     * @return \Helori\PhpSign\Elements\Webhook
     */
    public function formatWebhook(array $requestData)
    {
        $envelopeId = $requestData['data']['envelopeId'] ?? $requestData['envelopeId'] ?? null;

        if(!is_string($envelopeId) || $envelopeId === ''){
            throw new ValidationException('The Docusign webhook carries no envelope id');
        }

        $webhook = new Webhook();
        $webhook->setTransactionId($envelopeId);
        $webhook->setTransactionStatus($this->webhookStatus((string) ($requestData['event'] ?? '')));

        return $webhook;
    }

    /**
     * Whether a Connect message was signed with one of the account's HMAC keys.
     * Pass the raw request body: decoding and re-encoding the JSON changes its
     * bytes and breaks the signature.
     *
     * @param  string  $payload  the raw request body
     * @param  array<string>  $signatures  the values of the X-DocuSign-Signature-N headers
     * @param  array<string>  $secrets  the HMAC keys, several during a key rotation
     * @return bool
     */
    public static function isValidWebhookSignature(string $payload, array $signatures, array $secrets): bool
    {
        foreach($secrets as $secret){

            if(!is_string($secret) || $secret === ''){
                continue;
            }

            $expected = base64_encode(hash_hmac('sha256', $payload, $secret, true));

            foreach($signatures as $signature){
                if(is_string($signature) && hash_equals($expected, trim($signature))){
                    return true;
                }
            }
        }

        return false;
    }

    // ---------------------------------------------------------------
    // Envelope definition
    // ---------------------------------------------------------------

    protected function envelopeDefinition(Scenario $scenario): array
    {
        $documents = array_values($scenario->getDocuments() ?? []);
        $signers = array_values($scenario->getSigners() ?? []);

        if(empty($documents)){
            throw new ValidationException('A Docusign envelope needs at least one document');
        }

        if(empty($signers)){
            throw new ValidationException('A Docusign envelope needs at least one signer');
        }

        $subject = $this->subject($scenario);

        $envelope = [
            'emailSubject' => $subject,
            'status' => 'sent',
            'documents' => array_map(fn (Document $document) => $this->documentDefinition($document), $documents),
            'recipients' => [
                'signers' => array_map(
                    fn (Signer $signer, int $index) => $this->signerDefinition($scenario, $signer, $index, $subject),
                    $signers,
                    array_keys($signers)
                ),
            ],
            'notification' => [
                'useAccountDefaults' => 'false',
                'reminders' => [
                    'reminderEnabled' => 'false',
                ],
                'expirations' => [
                    'expireEnabled' => 'true',
                    'expireAfter' => (string) $this->getExpirationDays(),
                    'expireWarn' => '0',
                ],
            ],
        ];

        $customFields = $this->customFieldsDefinition($scenario);
        if(!empty($customFields)){
            $envelope['customFields'] = ['textCustomFields' => $customFields];
        }

        if(!empty($scenario->getStatusUrl())){
            $envelope['eventNotification'] = [
                'url' => $scenario->getStatusUrl(),
                'loggingEnabled' => 'true',
                'requireAcknowledgment' => 'true',
                'includeHMAC' => 'true',
                // JSON SIM messages: Docusign refuses "events" without it
                'deliveryMode' => 'SIM',
                'events' => self::WEBHOOK_EVENTS,
                'eventData' => [
                    'version' => 'restv2.1',
                    'format' => 'json',
                ],
            ];
        }

        return $envelope;
    }

    protected function subject(Scenario $scenario): string
    {
        $title = trim((string) $scenario->getTitle());

        return mb_substr($title === '' ? 'Signature' : $title, 0, 100);
    }

    /**
     * Docusign caps a custom field value at 100 characters. A longer return
     * URL is left out: the caller must then pass it to createSigningUrl().
     */
    protected function customFieldsDefinition(Scenario $scenario): array
    {
        $values = [
            'customId' => (string) $scenario->getCustomId(),
            'returnUrl' => (string) $scenario->getSuccessUrl(),
        ];

        $fields = [];
        foreach($values as $name => $value){
            if($value !== '' && mb_strlen($value) <= 100){
                $fields[] = [
                    'name' => $name,
                    'value' => $value,
                    'show' => 'false',
                    'required' => 'false',
                ];
            }
        }

        return $fields;
    }

    protected function documentDefinition(Document $document): array
    {
        $filepath = $document->getFilepath();

        if(empty($filepath) || !is_readable($filepath)){
            throw new ValidationException('The document "'.$document->getName().'" has no readable file');
        }

        $definition = [
            'documentId' => (string) $document->getId(),
            'name' => $document->getName() ?: 'Document '.$document->getId(),
            'fileExtension' => 'pdf',
            'documentBase64' => base64_encode(file_get_contents($filepath)),
        ];

        $fields = [];
        foreach($document->getMetadata() ?? [] as $name => $value){
            $fields[] = ['name' => (string) $name, 'value' => (string) $value];
        }

        if(!empty($fields)){
            $definition['documentFields'] = $fields;
        }

        return $definition;
    }

    protected function signerDefinition(Scenario $scenario, Signer $signer, int $index, string $subject): array
    {
        $signerId = (string) $signer->getId();

        if(empty($signer->getPhone())){
            throw new ValidationException('Signer "'.$signerId.'" has no phone number: Docusign phone authentication needs one');
        }

        $sequential = $scenario->getInvitationMode() === Scenario::INVITATION_MODE_CHAIN;

        return [
            'recipientId' => $signerId,
            'routingOrder' => (string) ($sequential ? $index + 1 : 1),
            'clientUserId' => $signerId,
            'name' => mb_substr(trim($signer->getFirstname().' '.$signer->getLastname()), 0, 100),
            'email' => $signer->getEmail(),
            'customFields' => [
                mb_substr(self::FIRSTNAME_FIELD.$signer->getFirstname(), 0, 100),
                mb_substr(self::LASTNAME_FIELD.$signer->getLastname(), 0, 100),
            ],
            'identityVerification' => [
                'workflowId' => $this->phoneWorkflowId(),
                'inputOptions' => [
                    [
                        'name' => 'phone_number_list',
                        'valueType' => 'PhoneNumberList',
                        'phoneNumberList' => [$this->phoneNumber($signer->getPhone(), $signerId)],
                    ],
                ],
            ],
            'emailNotification' => [
                'emailSubject' => $subject,
                'supportedLanguage' => $scenario->getLang(),
            ],
            'tabs' => $this->tabs($scenario, $signer->getId()),
        ];
    }

    /**
     * The Signature element follows PDF coordinates: points, origin at the
     * bottom-left corner of the page, (x, y) the bottom-left corner of the
     * rectangle. Docusign measures from the top-left corner of the page and
     * places a tab by its top-left corner.
     */
    protected function tabs(Scenario $scenario, int $signerId): array
    {
        $signHereTabs = [];
        $textTabs = [];

        foreach($scenario->getSignatures() ?? [] as $signature){

            if($signature->getSignerId() !== $signerId){
                continue;
            }

            $x = (int) round((float) $signature->getX());
            $top = (int) max(0, round($this->pageHeight() - (float) $signature->getY() - (float) $signature->getHeight()));
            $label = (string) $signature->getLabel();
            $mention = (string) $signature->getMention();

            $position = [
                'documentId' => (string) $signature->getDocumentId(),
                'pageNumber' => (string) $signature->getPage(),
                'xPosition' => (string) $x,
            ];

            if($mention !== ''){
                $textTabs[] = $position + [
                    'yPosition' => (string) $top,
                    'tabLabel' => $label.' mention',
                    'value' => $mention,
                    'locked' => 'true',
                    'required' => 'false',
                    'font' => 'helvetica',
                    'fontSize' => 'size9',
                    'width' => (string) max(1, (int) round((float) $signature->getWidth())),
                ];
                $top += self::MENTION_LINE_HEIGHT;
            }

            $signHereTabs[] = $position + [
                'yPosition' => (string) $top,
                'tabLabel' => $label,
            ];
        }

        $tabs = ['signHereTabs' => $signHereTabs];

        if(!empty($textTabs)){
            $tabs['textTabs'] = $textTabs;
        }

        return $tabs;
    }

    protected function pageHeight(): float
    {
        return (float) ($this->option('page_height') ?? self::DEFAULT_PAGE_HEIGHT);
    }

    protected function phoneNumber(string $phone, string $signerId): array
    {
        $util = PhoneNumberUtil::getInstance();

        try{
            $number = $util->parse($phone, $this->option('phone_region') ?? 'FR');
        }catch(NumberParseException $e){
            throw new ValidationException('Signer "'.$signerId.'" has a phone number Docusign cannot read');
        }

        return [
            'countryCode' => (string) $number->getCountryCode(),
            'number' => $util->getNationalSignificantNumber($number),
        ];
    }

    protected function phoneWorkflowId(): string
    {
        $configured = $this->option('phone_workflow_id');
        if(!is_null($configured)){
            return $configured;
        }

        if(!is_null($this->phoneWorkflowId)){
            return $this->phoneWorkflowId;
        }

        $cacheKey = $this->cacheKey('phone-workflow');
        $cached = $this->cache ? $this->cache->get($cacheKey) : null;
        if(is_string($cached) && $cached !== ''){
            return $this->phoneWorkflowId = $cached;
        }

        $data = $this->api('GET', '/identity_verification');

        foreach($data['identityVerification'] ?? [] as $workflow){
            if(($workflow['defaultName'] ?? null) === self::PHONE_AUTHENTICATION_WORKFLOW && !empty($workflow['workflowId'])){
                $this->phoneWorkflowId = (string) $workflow['workflowId'];
                $this->cache?->set($cacheKey, $this->phoneWorkflowId, self::ACCOUNT_CACHE_SECONDS);
                return $this->phoneWorkflowId;
            }
        }

        throw new SignException('Phone authentication is not enabled on this Docusign account');
    }

    // ---------------------------------------------------------------
    // Reading envelopes
    // ---------------------------------------------------------------

    protected function envelope(string $transactionId): array
    {
        return $this->api('GET', '/envelopes/'.rawurlencode($transactionId), [
            'query' => ['include' => 'recipients,custom_fields'],
        ]);
    }

    protected function transactionFrom(array $envelope): Transaction
    {
        $transaction = new Transaction($this->getName());
        $transaction->setId((string) $envelope['envelopeId']);
        $transaction->setStatus($this->transactionStatus($envelope));
        $transaction->setTitle((string) ($envelope['emailSubject'] ?? ''));

        $createdAt = DateParser::parse($envelope['createdDateTime'] ?? null);
        $expireAt = DateParser::parse($envelope['expireDateTime'] ?? null);
        $transaction->setCreatedAt($createdAt);
        $transaction->setExpireAt($expireAt ?? $createdAt?->copy()->addDays($this->getExpirationDays()));

        $customFields = $this->textCustomFields($envelope);
        if(isset($customFields['customId'])){
            $transaction->setCustomId($customFields['customId']);
        }

        $signers = array_map(fn (array $recipient) => $this->signerFrom($recipient), $envelope['recipients']['signers'] ?? []);
        usort($signers, fn (SignerResult $a, SignerResult $b) => $a->getId() <=> $b->getId());
        $transaction->setSigners($signers);

        return $transaction;
    }

    /**
     * No signing URL: Docusign's expire within minutes, see createSigningUrl().
     */
    protected function signerFrom(array $recipient): SignerResult
    {
        $signer = new SignerResult();
        $signer->setId((int) ($recipient['recipientId'] ?? 0));

        $names = $this->namesFrom($recipient);
        if(!is_null($names)){
            $signer->setFirstname($names[0]);
            $signer->setLastname($names[1]);
        }

        if(!empty($recipient['email'])){
            $signer->setEmail($recipient['email']);
        }

        $phone = $this->phoneFrom($recipient);
        if(!is_null($phone)){
            $signer->setPhone($phone);
        }

        $docusignStatus = strtolower((string) ($recipient['status'] ?? ''));
        $signer->setStatus($this->signerStatus($docusignStatus));
        $signer->setActionAt($this->actionDate($recipient, $docusignStatus));

        if($docusignStatus === 'declined' && !empty($recipient['declinedReason'])){
            $signer->setError((string) $recipient['declinedReason']);
        }else if($docusignStatus === 'authenticationfailed'){
            $signer->setError('Phone authentication failed');
        }

        return $signer;
    }

    /**
     * @return array{0: string, 1: string}|null
     */
    protected function namesFrom(array $recipient): ?array
    {
        $firstname = null;
        $lastname = null;

        foreach($recipient['customFields'] ?? [] as $field){
            if(is_string($field) && str_starts_with($field, self::FIRSTNAME_FIELD)){
                $firstname = substr($field, strlen(self::FIRSTNAME_FIELD));
            }else if(is_string($field) && str_starts_with($field, self::LASTNAME_FIELD)){
                $lastname = substr($field, strlen(self::LASTNAME_FIELD));
            }
        }

        if(!is_null($firstname) && !is_null($lastname)){
            return [$firstname, $lastname];
        }

        // Envelope created without the name fields: Docusign's full name
        // is all there is, its first word taken as the first name.
        $name = trim((string) ($recipient['name'] ?? ''));
        if($name === ''){
            return null;
        }

        $parts = preg_split('/\s+/', $name, 2);

        return count($parts) === 2 ? [$parts[0], $parts[1]] : ['', $parts[0]];
    }

    protected function phoneFrom(array $recipient): ?string
    {
        foreach($recipient['identityVerification']['inputOptions'] ?? [] as $option){
            foreach($option['phoneNumberList'] ?? [] as $phone){
                if(!empty($phone['countryCode']) && !empty($phone['number'])){
                    return '+'.$phone['countryCode'].$phone['number'];
                }
            }
        }

        return null;
    }

    protected function actionDate(array $recipient, string $docusignStatus): ?Carbon
    {
        $field = [
            'signed' => 'signedDateTime',
            'completed' => 'signedDateTime',
            'declined' => 'declinedDateTime',
            'delivered' => 'deliveredDateTime',
            'sent' => 'sentDateTime',
        ][$docusignStatus] ?? null;

        if(is_null($field) || empty($recipient[$field])){
            return null;
        }

        return DateParser::parse($recipient[$field]);
    }

    protected function textCustomFields(array $envelope): array
    {
        $values = [];

        foreach($envelope['customFields']['textCustomFields'] ?? [] as $field){
            if(isset($field['name'])){
                $values[$field['name']] = $field['value'] ?? null;
            }
        }

        return $values;
    }

    protected function transactionStatus(array $envelope): string
    {
        switch(strtolower((string) ($envelope['status'] ?? ''))){

            case 'created':
                return Transaction::STATUS_DRAFT;

            // "signed": every recipient signed, Docusign is still completing the envelope
            case 'sent':
            case 'delivered':
            case 'correct':
            case 'signed':
                return Transaction::STATUS_READY;

            case 'completed':
                return Transaction::STATUS_COMPLETED;

            case 'declined':
                return Transaction::STATUS_REFUSED;

            // Docusign voids an envelope when it expires
            case 'voided':
                return $this->voidedOnExpiry($envelope) ? Transaction::STATUS_EXPIRED : Transaction::STATUS_CANCELED;

            case 'deleted':
                return Transaction::STATUS_CANCELED;

            case 'timedout':
                return Transaction::STATUS_EXPIRED;

            default:
                return Transaction::STATUS_UNKNOWN;
        }
    }

    protected function voidedOnExpiry(array $envelope): bool
    {
        if(str_contains(strtolower((string) ($envelope['voidedReason'] ?? '')), 'expire')){
            return true;
        }

        $expireAt = DateParser::parse($envelope['expireDateTime'] ?? null);
        $voidedAt = DateParser::parse($envelope['voidedDateTime'] ?? null);

        return !is_null($expireAt) && !is_null($voidedAt) && $voidedAt->gte($expireAt);
    }

    protected function signerStatus(string $docusignStatus): string
    {
        switch($docusignStatus){

            // Not their turn yet
            case 'created':
                return SignerResult::STATUS_WAITING;

            // A failed phone authentication can be tried again from a new signing URL
            case 'sent':
            case 'autoresponded':
            case 'authenticationfailed':
                return SignerResult::STATUS_READY;

            case 'delivered':
                return SignerResult::STATUS_ACCESSED;

            case 'signed':
            case 'completed':
                return SignerResult::STATUS_SIGNED;

            case 'declined':
                return SignerResult::STATUS_CANCELED;

            default:
                return SignerResult::STATUS_UNKNOWN;
        }
    }

    protected function webhookStatus(string $event): string
    {
        switch($event){

            case 'envelope-completed':
                return Transaction::STATUS_COMPLETED;

            case 'envelope-declined':
                return Transaction::STATUS_REFUSED;

            // An expired envelope is voided too: read the envelope to tell them apart
            case 'envelope-voided':
                return Transaction::STATUS_CANCELED;

            case 'envelope-sent':
            case 'envelope-delivered':
            case 'envelope-resent':
            case 'recipient-sent':
            case 'recipient-delivered':
            case 'recipient-completed':
            case 'recipient-declined':
            case 'recipient-authenticationfailed':
                return Transaction::STATUS_READY;

            default:
                return Transaction::STATUS_UNKNOWN;
        }
    }

    // ---------------------------------------------------------------
    // HTTP and authentication
    // ---------------------------------------------------------------

    protected function api(string $method, string $path, array $options = []): array
    {
        return $this->decoded($this->send($method, $this->accountUrl($path), $options));
    }

    protected function download(string $path): string
    {
        $response = $this->send('GET', $this->accountUrl($path), ['headers' => ['Accept' => 'application/pdf']]);

        if($response->getStatusCode() >= 400){
            throw $this->apiError($response);
        }

        return (string) $response->getBody();
    }

    protected function accountUrl(string $path): string
    {
        $account = $this->account();

        return $account['base_uri'].'/restapi/v2.1/accounts/'.rawurlencode($account['account_id']).$path;
    }

    /**
     * Send an authenticated request, renewing the access token once when
     * Docusign rejects it (revoked, or expired before its announced time).
     */
    protected function send(string $method, string $url, array $options = []): ResponseInterface
    {
        $options['http_errors'] = false;
        $options['headers'] = ($options['headers'] ?? []) + ['Accept' => 'application/json'];
        $options['headers']['Authorization'] = 'Bearer '.$this->accessToken();

        $response = $this->client->request($method, $url, $options);

        if($response->getStatusCode() === 401){
            $options['headers']['Authorization'] = 'Bearer '.$this->accessToken(true);
            $response = $this->client->request($method, $url, $options);
        }

        return $response;
    }

    protected function accessToken(bool $renew = false): string
    {
        $cacheKey = $this->cacheKey('token');

        if(!$renew){
            if(!is_null($this->accessToken)){
                return $this->accessToken;
            }

            $cached = $this->cache ? $this->cache->get($cacheKey) : null;
            if(is_string($cached) && $cached !== ''){
                return $this->accessToken = $cached;
            }
        }

        $now = time();

        try{
            $assertion = JWT::encode([
                'iss' => $this->config['integrator_key'],
                'sub' => $this->config['user_id'],
                'aud' => $this->authHost,
                'iat' => $now,
                'exp' => $now + self::TOKEN_LIFETIME_SECONDS,
                'scope' => 'signature impersonation',
            ], $this->config['private_key'], 'RS256');
        }catch(\Throwable $e){
            // Never echo the key: the exception message may quote it
            throw new DriverAuthException('The Docusign private key cannot sign the JWT assertion');
        }

        $response = $this->client->request('POST', 'https://'.$this->authHost.'/oauth/token', [
            'form_params' => [
                'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion' => $assertion,
            ],
            'headers' => ['Accept' => 'application/json'],
            'http_errors' => false,
        ]);

        $data = json_decode((string) $response->getBody(), true);
        $data = is_array($data) ? $data : [];

        if($response->getStatusCode() >= 400 || empty($data['access_token'])){

            if(($data['error'] ?? null) === 'consent_required'){
                $consentUrl = $this->getConsentUrl();
                throw new DriverAuthException(is_null($consentUrl)
                    ? 'The Docusign user has not granted consent to the integration key: set "redirect_uri" to get the consent URL'
                    : 'The Docusign user has not granted consent to the integration key: open '.$consentUrl.' once, logged in as that user'
                );
            }

            throw new DriverAuthException('Docusign refused the JWT grant (HTTP '.$response->getStatusCode().'): '
                .($data['error'] ?? 'no error code').(isset($data['error_description']) ? ', '.$data['error_description'] : ''));
        }

        $ttl = max(60, (int) ($data['expires_in'] ?? self::TOKEN_LIFETIME_SECONDS) - self::TOKEN_RENEWAL_MARGIN_SECONDS);
        $this->cache?->set($cacheKey, $data['access_token'], $ttl);

        return $this->accessToken = $data['access_token'];
    }

    /**
     * The account's API host (base_uri) depends on its data center, for
     * example https://eu.docusign.net. Docusign rate-limits userinfo, so the
     * answer is cached.
     *
     * @return array{account_id: string, base_uri: string}
     */
    protected function account(): array
    {
        if(!is_null($this->account)){
            return $this->account;
        }

        $cacheKey = $this->cacheKey('account');
        $cached = $this->cache ? $this->cache->get($cacheKey) : null;
        if(is_array($cached) && !empty($cached['account_id']) && !empty($cached['base_uri'])){
            return $this->account = $cached;
        }

        $data = $this->decoded($this->send('GET', 'https://'.$this->authHost.'/oauth/userinfo'));
        $wanted = $this->option('account_id');
        $account = null;

        foreach($data['accounts'] ?? [] as $candidate){
            $matches = is_null($wanted)
                ? filter_var($candidate['is_default'] ?? false, FILTER_VALIDATE_BOOLEAN)
                : ($candidate['account_id'] ?? null) === $wanted;

            if($matches){
                $account = $candidate;
                break;
            }
        }

        if(is_null($account)){
            throw new DriverAuthException(is_null($wanted)
                ? 'The Docusign user has no default account'
                : 'The Docusign user has no access to the account "'.$wanted.'"'
            );
        }

        $this->account = [
            'account_id' => (string) $account['account_id'],
            'base_uri' => rtrim((string) $account['base_uri'], '/'),
        ];
        $this->cache?->set($cacheKey, $this->account, self::ACCOUNT_CACHE_SECONDS);

        return $this->account;
    }

    protected function decoded(ResponseInterface $response): array
    {
        if($response->getStatusCode() >= 400){
            throw $this->apiError($response);
        }

        $body = (string) $response->getBody();
        if($body === ''){
            return [];
        }

        $data = json_decode($body, true);
        if(!is_array($data)){
            throw new SignException('Docusign returned an unreadable response (HTTP '.$response->getStatusCode().')');
        }

        return $data;
    }

    protected function apiError(ResponseInterface $response): SignException
    {
        $status = $response->getStatusCode();
        $data = json_decode((string) $response->getBody(), true);
        $code = is_array($data) ? ($data['errorCode'] ?? null) : null;
        $message = is_array($data) && !empty($data['message']) ? $data['message'] : $response->getReasonPhrase();
        $text = 'Docusign API error (HTTP '.$status.')'.($code ? ' '.$code : '').': '.$message;

        if($status === 404 || $code === 'ENVELOPE_DOES_NOT_EXIST'){
            return new NotFoundException($text, $status);
        }

        return new SignException($text, $status);
    }

    protected function cacheKey(string $name): string
    {
        return 'php-sign.docusign.'.$name.'.'.sha1(implode('|', [
            $this->config['mode'],
            $this->config['integrator_key'],
            $this->config['user_id'],
            (string) $this->option('account_id'),
        ]));
    }

    /**
     * A config value, null when missing or empty (unset environment variables
     * often arrive as empty strings)
     */
    protected function option(string $key)
    {
        $value = $this->config[$key] ?? null;

        return $value === '' ? null : $value;
    }
}
