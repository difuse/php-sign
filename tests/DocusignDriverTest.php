<?php

namespace Helori\PhpSign\Test;

use Carbon\Carbon;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Helori\PhpSign\Drivers\DocusignDriver;
use Helori\PhpSign\Elements\Document;
use Helori\PhpSign\Elements\Requester;
use Helori\PhpSign\Elements\Scenario;
use Helori\PhpSign\Elements\Signature;
use Helori\PhpSign\Elements\Signer;
use Helori\PhpSign\Elements\SignerResult;
use Helori\PhpSign\Elements\Transaction;
use Helori\PhpSign\Exceptions\DriverAuthException;
use Helori\PhpSign\Exceptions\NotFoundException;
use Helori\PhpSign\Exceptions\SignException;
use Helori\PhpSign\Exceptions\ValidationException;
use Helori\PhpSign\Test\Support\ArrayCache;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;


class DocusignDriverTest extends TestCase
{
    const API = 'https://demo.docusign.net/restapi/v2.1/accounts/ACC-1';

    private static string $privateKey;

    /** @var array<int, array{request: RequestInterface}> */
    private array $history = [];

    public static function setUpBeforeClass(): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $pem);
        self::$privateKey = $pem;
    }

    public function testMakesNoRequestBeforeTheFirstCall(): void
    {
        $this->driver([]);

        $this->assertSame([], $this->history);
    }

    public function testRequesterLoadsTheDriverByName(): void
    {
        $requester = new Requester('docusign', $this->config([]));

        $this->assertInstanceOf(DocusignDriver::class, $requester->getDriver());
    }

    public function testRejectsAConfigWithoutPrivateKey(): void
    {
        $this->expectException(ValidationException::class);

        new DocusignDriver(['mode' => 'dev', 'integrator_key' => 'IK', 'user_id' => 'USER', 'private_key' => '']);
    }

    public function testCreatesAnEmbeddedEnvelopeWithPhoneAuthentication(): void
    {
        $driver = $this->driver([
            ...$this->authResponses(),
            $this->json(['identityVerification' => [
                ['workflowId' => 'WF-ID-CHECK', 'defaultName' => 'ID Verification'],
                ['workflowId' => 'WF-PHONE', 'defaultName' => 'Phone Authentication'],
            ]]),
            $this->json(['envelopeId' => 'ENV-1', 'status' => 'sent'], 201),
            $this->json($this->envelope('sent', [
                $this->recipient(1, 'sent', 'Jean Pierre', 'DE LA TOUR'),
                $this->recipient(2, 'created', 'Marie', 'DE LA TOUR'),
            ])),
        ]);

        $transaction = $driver->createTransaction($this->scenario());

        $tokenRequest = $this->request(0);
        $this->assertSame('https://account-d.docusign.com/oauth/token', (string) $tokenRequest->getUri());
        parse_str((string) $tokenRequest->getBody(), $form);
        $this->assertSame('urn:ietf:params:oauth:grant-type:jwt-bearer', $form['grant_type']);
        $claims = json_decode(base64_decode(strtr(explode('.', $form['assertion'])[1], '-_', '+/')), true);
        $this->assertSame('IK', $claims['iss']);
        $this->assertSame('USER', $claims['sub']);
        $this->assertSame('account-d.docusign.com', $claims['aud']);
        $this->assertSame('signature impersonation', $claims['scope']);
        $this->assertLessThanOrEqual(3600, $claims['exp'] - $claims['iat']);

        $this->assertSame(self::API.'/identity_verification', (string) $this->request(2)->getUri());

        $create = $this->request(3);
        $this->assertSame('POST', $create->getMethod());
        $this->assertSame(self::API.'/envelopes', (string) $create->getUri());
        $this->assertSame('Bearer TOKEN-1', $create->getHeaderLine('Authorization'));

        $envelope = json_decode((string) $create->getBody(), true);
        $this->assertSame('sent', $envelope['status']);
        $this->assertSame('Affaire n°12', $envelope['emailSubject']);
        $this->assertSame('14', $envelope['notification']['expirations']['expireAfter']);
        $this->assertSame([
            ['name' => 'customId', 'value' => '77', 'show' => 'false', 'required' => 'false'],
            ['name' => 'returnUrl', 'value' => 'https://wime.test/associe?r=signature', 'show' => 'false', 'required' => 'false'],
        ], $envelope['customFields']['textCustomFields']);

        $document = $envelope['documents'][0];
        $this->assertSame('1', $document['documentId']);
        $this->assertSame([['name' => 'contractId', 'value' => '42']], $document['documentFields']);
        $this->assertSame(file_get_contents($this->pdf()), base64_decode($document['documentBase64']));

        [$main, $coSubscriber] = $envelope['recipients']['signers'];
        $this->assertSame('1', $main['recipientId']);
        $this->assertSame('1', $main['routingOrder']);
        $this->assertSame('2', $coSubscriber['routingOrder']);
        $this->assertSame('1', $main['clientUserId']);
        // Signer normalizes names: first name capitalized, last name upper case
        $this->assertSame('Jean pierre DE LA TOUR', $main['name']);
        $this->assertSame(['firstname:Jean pierre', 'lastname:DE LA TOUR'], $main['customFields']);
        $this->assertSame('WF-PHONE', $main['identityVerification']['workflowId']);
        $this->assertSame(
            [['countryCode' => '33', 'number' => '612345678']],
            $main['identityVerification']['inputOptions'][0]['phoneNumberList']
        );
        $this->assertSame(
            [['countryCode' => '33', 'number' => '698765432']],
            $coSubscriber['identityVerification']['inputOptions'][0]['phoneNumberList']
        );
        $this->assertSame('fr', $main['emailNotification']['supportedLanguage']);

        // Rect [100, 200, 150, 60] from the bottom of an 841-point page:
        // its top is 841 - 200 - 60 = 581 from the top, the mention takes 12
        $this->assertSame([[
            'documentId' => '1',
            'pageNumber' => '2',
            'xPosition' => '100',
            'yPosition' => '581',
            'tabLabel' => 'Souscripteur mention',
            'value' => 'Lu et approuvé',
            'locked' => 'true',
            'required' => 'false',
            'font' => 'helvetica',
            'fontSize' => 'size9',
            'width' => '150',
        ]], $main['tabs']['textTabs']);
        $this->assertSame([[
            'documentId' => '1',
            'pageNumber' => '2',
            'xPosition' => '100',
            'yPosition' => '593',
            'tabLabel' => 'Souscripteur',
        ]], $main['tabs']['signHereTabs']);
        $this->assertArrayNotHasKey('textTabs', $coSubscriber['tabs']);
        $this->assertSame('300', $coSubscriber['tabs']['signHereTabs'][0]['xPosition']);
        $this->assertSame('581', $coSubscriber['tabs']['signHereTabs'][0]['yPosition']);

        $notification = $envelope['eventNotification'];
        $this->assertSame('https://wime.test/webhook/docusign', $notification['url']);
        $this->assertSame('true', $notification['includeHMAC']);
        $this->assertSame('true', $notification['requireAcknowledgment']);
        $this->assertContains('envelope-completed', $notification['events']);
        $this->assertSame(['version' => 'restv2.1', 'format' => 'json'], $notification['eventData']);

        $this->assertSame('ENV-1', $transaction->getId());
        $this->assertSame(Transaction::STATUS_READY, $transaction->getStatus());
        $this->assertSame('77', $transaction->getCustomId());

        [$first, $second] = $transaction->getSigners();
        $this->assertSame('Jean pierre', $first->getFirstname());
        $this->assertSame('DE LA TOUR', $first->getLastname());
        $this->assertSame('+33612345678', $first->getPhone());
        $this->assertSame(SignerResult::STATUS_READY, $first->getStatus());
        $this->assertNull($first->getUrl());
        $this->assertSame(SignerResult::STATUS_WAITING, $second->getStatus());
    }

    public function testSignsInParallelOutsideTheChainMode(): void
    {
        $driver = $this->driver([
            ...$this->authResponses(),
            $this->json(['envelopeId' => 'ENV-1'], 201),
            $this->json($this->envelope('sent', [$this->recipient(1, 'sent'), $this->recipient(2, 'sent')])),
        ], ['phone_workflow_id' => 'WF-PHONE']);

        $scenario = $this->scenario();
        $scenario->setInvitationMode(Scenario::INVITATION_MODE_EMAIL);
        $driver->createTransaction($scenario);

        $signers = json_decode((string) $this->request(2)->getBody(), true)['recipients']['signers'];
        $this->assertSame(['1', '1'], array_column($signers, 'routingOrder'));
    }

    public function testLeavesOutAReturnUrlTooLongForACustomField(): void
    {
        $driver = $this->driver([
            ...$this->authResponses(),
            $this->json(['envelopeId' => 'ENV-1'], 201),
            $this->json($this->envelope('sent', [$this->recipient(1, 'sent')])),
        ], ['phone_workflow_id' => 'WF-PHONE']);

        $scenario = $this->scenario();
        $scenario->setSuccessUrl('https://wime.test/'.str_repeat('a', 100));
        $driver->createTransaction($scenario);

        $fields = json_decode((string) $this->request(2)->getBody(), true)['customFields']['textCustomFields'];
        $this->assertSame(['customId'], array_column($fields, 'name'));
    }

    public function testRefusesASignerWithoutPhoneBeforeAnyRequest(): void
    {
        $driver = $this->driver([], ['phone_workflow_id' => 'WF-PHONE']);

        $withoutPhone = $this->signer(2, 'Marie', null);
        $scenario = $this->scenario([$this->signer(1, 'Jean Pierre', '+33612345678'), $withoutPhone]);

        try{
            $driver->createTransaction($scenario);
            $this->fail('A signer without phone was accepted');
        }catch(ValidationException $e){
            $this->assertStringContainsString('Signer "2" has no phone number', $e->getMessage());
        }

        $this->assertSame([], $this->history);
    }

    public function testFailsWhenPhoneAuthenticationIsNotEnabled(): void
    {
        $driver = $this->driver([
            ...$this->authResponses(),
            $this->json(['identityVerification' => []]),
        ]);

        $this->expectException(SignException::class);
        $this->expectExceptionMessage('Phone authentication is not enabled');

        $driver->createTransaction($this->scenario());
    }

    public function testReadsACompletedEnvelopeInOneRequest(): void
    {
        $driver = $this->driver([
            ...$this->authResponses(),
            $this->json($this->envelope('completed', [
                $this->recipient(1, 'completed', 'Jean Pierre', 'DE LA TOUR', ['signedDateTime' => '2026-11-12T10:15:30.1230000Z']),
            ], ['expireDateTime' => '2026-11-26T09:00:00.0000000Z'])),
        ]);

        $transaction = $driver->getTransaction('ENV-1');

        $this->assertCount(3, $this->history);
        $this->assertSame(self::API.'/envelopes/ENV-1?include=recipients%2Ccustom_fields', (string) $this->request(2)->getUri());
        $this->assertSame(Transaction::STATUS_COMPLETED, $transaction->getStatus());
        $this->assertTrue(Carbon::parse('2026-11-12 09:00:00', 'UTC')->equalTo($transaction->getCreatedAt()));
        $this->assertTrue(Carbon::parse('2026-11-26 09:00:00', 'UTC')->equalTo($transaction->getExpireAt()));

        $signer = $transaction->getSigners()[0];
        $this->assertSame(SignerResult::STATUS_SIGNED, $signer->getStatus());
        $this->assertSame('2026-11-12 10:15:30', $signer->getActionAt()->format('Y-m-d H:i:s'));
    }

    public function testFallsBackOnTheFullNameWithoutNameFields(): void
    {
        $recipient = $this->recipient(1, 'sent', 'Jean', 'DUPONT');
        unset($recipient['customFields'], $recipient['identityVerification']);

        $driver = $this->driver([
            ...$this->authResponses(),
            $this->json($this->envelope('sent', [$recipient])),
        ]);

        $signer = $driver->getTransaction('ENV-1')->getSigners()[0];

        $this->assertSame('Jean', $signer->getFirstname());
        $this->assertSame('DUPONT', $signer->getLastname());
        $this->assertNull($signer->getPhone());
    }

    #[DataProvider('envelopeStatuses')]
    public function testMapsEnvelopeStatuses(array $envelope, string $expected): void
    {
        $driver = $this->driver([
            ...$this->authResponses(),
            $this->json($this->envelope($envelope['status'], [$this->recipient(1, 'sent')], $envelope)),
        ]);

        $this->assertSame($expected, $driver->getTransaction('ENV-1')->getStatus());
    }

    public static function envelopeStatuses(): array
    {
        return [
            'created' => [['status' => 'created'], Transaction::STATUS_DRAFT],
            'sent' => [['status' => 'sent'], Transaction::STATUS_READY],
            'delivered' => [['status' => 'delivered'], Transaction::STATUS_READY],
            'all signed, not completed yet' => [['status' => 'signed'], Transaction::STATUS_READY],
            'completed' => [['status' => 'completed'], Transaction::STATUS_COMPLETED],
            'declined' => [['status' => 'declined'], Transaction::STATUS_REFUSED],
            'voided by the sender' => [['status' => 'voided', 'voidedReason' => DocusignDriver::VOIDED_REASON], Transaction::STATUS_CANCELED],
            'voided on expiry, by reason' => [['status' => 'voided', 'voidedReason' => 'Envelope has expired.'], Transaction::STATUS_EXPIRED],
            'voided on expiry, by date' => [[
                'status' => 'voided',
                'voidedReason' => '',
                'expireDateTime' => '2026-11-26T09:00:00Z',
                'voidedDateTime' => '2026-11-26T09:03:00Z',
            ], Transaction::STATUS_EXPIRED],
            'unknown' => [['status' => 'template'], Transaction::STATUS_UNKNOWN],
        ];
    }

    #[DataProvider('signerStatuses')]
    public function testMapsSignerStatuses(string $docusignStatus, string $expected): void
    {
        $driver = $this->driver([
            ...$this->authResponses(),
            $this->json($this->envelope('sent', [$this->recipient(1, $docusignStatus)])),
        ]);

        $this->assertSame($expected, $driver->getTransaction('ENV-1')->getSigners()[0]->getStatus());
    }

    public static function signerStatuses(): array
    {
        return [
            'not their turn' => ['created', SignerResult::STATUS_WAITING],
            'sent' => ['sent', SignerResult::STATUS_READY],
            'failed phone authentication' => ['authenticationfailed', SignerResult::STATUS_READY],
            'opened the page' => ['delivered', SignerResult::STATUS_ACCESSED],
            'signed' => ['signed', SignerResult::STATUS_SIGNED],
            'completed' => ['completed', SignerResult::STATUS_SIGNED],
            'declined' => ['declined', SignerResult::STATUS_CANCELED],
            'unknown' => ['faxpending', SignerResult::STATUS_UNKNOWN],
        ];
    }

    public function testDownloadsTheSignedDocumentsWithTheirMetadata(): void
    {
        $driver = $this->driver([
            ...$this->authResponses(),
            $this->json(['envelopeDocuments' => [
                ['documentId' => '1', 'name' => 'Bulletin', 'type' => 'content'],
                ['documentId' => 'certificate', 'name' => 'Summary', 'type' => 'summary'],
            ]]),
            $this->json(['documentFields' => [['name' => 'contractId', 'value' => '42']]]),
            new Response(200, ['Content-Type' => 'application/pdf'], '%PDF-signed'),
        ]);

        $documents = $driver->getDocuments('ENV-1');

        $this->assertCount(1, $documents);
        $this->assertSame(1, $documents[0]->getId());
        $this->assertSame('Bulletin', $documents[0]->getName());
        $this->assertSame(['contractId' => '42'], $documents[0]->getMetadata());
        $this->assertSame('%PDF-signed', $documents[0]->getContent());
        $this->assertSame(self::API.'/envelopes/ENV-1/documents/1/fields', (string) $this->request(3)->getUri());
        $this->assertSame(self::API.'/envelopes/ENV-1/documents/1', (string) $this->request(4)->getUri());
        $this->assertSame('application/pdf', $this->request(4)->getHeaderLine('Accept'));
    }

    public function testDownloadsTheCertificate(): void
    {
        $driver = $this->driver([
            ...$this->authResponses(),
            new Response(200, ['Content-Type' => 'application/pdf'], '%PDF-certificate'),
        ]);

        $this->assertSame('%PDF-certificate', $driver->getCertificate('ENV-1'));
        $this->assertSame(self::API.'/envelopes/ENV-1/documents/certificate', (string) $this->request(2)->getUri());
    }

    public function testVoidsWithoutPurgingTheDocuments(): void
    {
        $driver = $this->driver([
            ...$this->authResponses(),
            $this->json(['envelopeId' => 'ENV-1']),
            $this->json($this->envelope('voided', [$this->recipient(1, 'sent')], ['voidedReason' => DocusignDriver::VOIDED_REASON])),
        ]);

        $transaction = $driver->cancelTransaction('ENV-1');

        $void = $this->request(2);
        $this->assertSame('PUT', $void->getMethod());
        $this->assertSame(['status' => 'voided', 'voidedReason' => DocusignDriver::VOIDED_REASON], json_decode((string) $void->getBody(), true));
        $this->assertSame(Transaction::STATUS_CANCELED, $transaction->getStatus());
    }

    public function testCreatesASigningUrlWithTheStoredReturnUrl(): void
    {
        $driver = $this->driver([
            ...$this->authResponses(),
            $this->json($this->envelope('sent', [$this->recipient(1, 'completed'), $this->recipient(2, 'sent', 'Marie', 'DE LA TOUR')])),
            $this->json(['url' => 'https://demo.docusign.net/Signing/StartInSession.aspx?t=abc'], 201),
        ]);

        $url = $driver->createSigningUrl('ENV-1', 2);

        $this->assertSame('https://demo.docusign.net/Signing/StartInSession.aspx?t=abc', $url);
        $this->assertSame(self::API.'/envelopes/ENV-1/views/recipient', (string) $this->request(3)->getUri());
        $this->assertSame([
            'returnUrl' => 'https://wime.test/associe?r=signature',
            'authenticationMethod' => 'Email',
            'clientUserId' => '2',
            'recipientId' => '2',
            'userName' => 'Marie DE LA TOUR',
            'email' => 'signer2@example.com',
        ], json_decode((string) $this->request(3)->getBody(), true));
    }

    public function testCreatesASigningUrlWithAGivenReturnUrl(): void
    {
        $driver = $this->driver([
            ...$this->authResponses(),
            $this->json($this->envelope('sent', [$this->recipient(1, 'sent')], ['customFields' => ['textCustomFields' => []]])),
            $this->json(['url' => 'https://demo.docusign.net/sign']),
        ]);

        $driver->createSigningUrl('ENV-1', 1, 'https://wime.test/back');

        $this->assertSame('https://wime.test/back', json_decode((string) $this->request(3)->getBody(), true)['returnUrl']);
    }

    public function testRefusesASigningUrlWithoutAnyReturnUrl(): void
    {
        $driver = $this->driver([
            ...$this->authResponses(),
            $this->json($this->envelope('sent', [$this->recipient(1, 'sent')], ['customFields' => ['textCustomFields' => []]])),
        ]);

        $this->expectException(ValidationException::class);

        $driver->createSigningUrl('ENV-1', 1);
    }

    public function testRefusesASigningUrlForAnUnknownSigner(): void
    {
        $driver = $this->driver([
            ...$this->authResponses(),
            $this->json($this->envelope('sent', [$this->recipient(1, 'sent')])),
        ]);

        $this->expectException(NotFoundException::class);

        $driver->createSigningUrl('ENV-1', 3);
    }

    public function testReusesTheCachedTokenAndAccountAcrossInstances(): void
    {
        $cache = new ArrayCache();
        $envelope = $this->json($this->envelope('sent', [$this->recipient(1, 'sent')]));

        $this->driver([...$this->authResponses(), $envelope], ['cache' => $cache])->getTransaction('ENV-1');
        $this->driver([$this->json($this->envelope('sent', [$this->recipient(1, 'sent')]))], ['cache' => $cache])->getTransaction('ENV-1');

        $this->assertCount(1, $this->history);
        $this->assertSame('Bearer TOKEN-1', $this->request(0)->getHeaderLine('Authorization'));
    }

    public function testRenewsARejectedTokenOnce(): void
    {
        $cache = new ArrayCache();

        $driver = $this->driver([
            ...$this->authResponses(),
            $this->json(['errorCode' => 'USER_AUTHENTICATION_FAILED'], 401),
            $this->json(['access_token' => 'TOKEN-2', 'expires_in' => 3600]),
            $this->json($this->envelope('sent', [$this->recipient(1, 'sent')])),
        ], ['cache' => $cache]);

        $driver->getTransaction('ENV-1');

        $this->assertSame('Bearer TOKEN-2', $this->request(4)->getHeaderLine('Authorization'));
        $this->assertContains('TOKEN-2', $cache->values);
    }

    public function testUsesTheConfiguredAccountAndItsDataCenter(): void
    {
        $driver = $this->driver([
            $this->json(['access_token' => 'TOKEN-1', 'expires_in' => 3600]),
            $this->json(['accounts' => [
                ['account_id' => 'ACC-1', 'is_default' => true, 'base_uri' => 'https://demo.docusign.net'],
                ['account_id' => 'ACC-EU', 'is_default' => false, 'base_uri' => 'https://eu.docusign.net/'],
            ]]),
            $this->json($this->envelope('sent', [$this->recipient(1, 'sent')])),
        ], ['account_id' => 'ACC-EU', 'mode' => 'production']);

        $driver->getTransaction('ENV-1');

        $this->assertSame('https://account.docusign.com/oauth/token', (string) $this->request(0)->getUri());
        $this->assertStringStartsWith('https://eu.docusign.net/restapi/v2.1/accounts/ACC-EU/envelopes/ENV-1', (string) $this->request(2)->getUri());
    }

    public function testGivesTheConsentUrlWhenConsentIsMissing(): void
    {
        $driver = $this->driver([
            $this->json(['error' => 'consent_required'], 400),
        ], ['redirect_uri' => 'http://localhost']);

        try{
            $driver->getTransaction('ENV-1');
            $this->fail('A missing consent went unnoticed');
        }catch(DriverAuthException $e){
            $this->assertStringContainsString(
                'https://account-d.docusign.com/oauth/auth?response_type=code&scope=signature+impersonation&client_id=IK&redirect_uri=http%3A%2F%2Flocalhost',
                $e->getMessage()
            );
        }
    }

    public function testNeverQuotesAnUnusablePrivateKey(): void
    {
        $driver = $this->driver([], ['private_key' => 'NOT-A-KEY']);

        try{
            $driver->getTransaction('ENV-1');
            $this->fail('An unusable private key went unnoticed');
        }catch(DriverAuthException $e){
            $this->assertStringNotContainsString('NOT-A-KEY', $e->getMessage());
        }
    }

    public function testReportsAMissingEnvelope(): void
    {
        $driver = $this->driver([
            ...$this->authResponses(),
            $this->json(['errorCode' => 'ENVELOPE_DOES_NOT_EXIST', 'message' => 'The envelope does not exist'], 400),
        ]);

        $this->expectException(NotFoundException::class);
        $this->expectExceptionMessage('ENVELOPE_DOES_NOT_EXIST: The envelope does not exist');

        $driver->getTransaction('ENV-404');
    }

    public function testReadsAConnectWebhook(): void
    {
        $webhook = $this->driver([])->formatWebhook([
            'event' => 'envelope-completed',
            'apiVersion' => 'v2.1',
            'data' => ['accountId' => 'ACC-1', 'envelopeId' => 'ENV-1'],
        ]);

        $this->assertSame('ENV-1', $webhook->getTransactionId());
        $this->assertSame(Transaction::STATUS_COMPLETED, $webhook->getTransactionStatus());
    }

    public function testRefusesAWebhookWithoutEnvelope(): void
    {
        $this->expectException(ValidationException::class);

        $this->driver([])->formatWebhook(['event' => 'envelope-completed', 'data' => []]);
    }

    public function testChecksTheWebhookSignature(): void
    {
        $payload = '{"event":"envelope-completed","data":{"envelopeId":"ENV-1"}}';
        $signature = base64_encode(hash_hmac('sha256', $payload, 'NEW-KEY', true));

        $this->assertTrue(DocusignDriver::isValidWebhookSignature($payload, ['other', $signature], ['OLD-KEY', 'NEW-KEY']));
        $this->assertFalse(DocusignDriver::isValidWebhookSignature($payload.' ', [$signature], ['NEW-KEY']));
        $this->assertFalse(DocusignDriver::isValidWebhookSignature($payload, [$signature], ['OLD-KEY']));
        $this->assertFalse(DocusignDriver::isValidWebhookSignature($payload, [$signature], ['']));
    }

    // ---------------------------------------------------------------

    private function driver(array $responses, array $config = []): DocusignDriver
    {
        $this->history = [];
        $stack = HandlerStack::create(new MockHandler($responses));
        $stack->push(Middleware::history($this->history));

        return new DocusignDriver($this->config(['client' => new Client(['handler' => $stack])] + $config));
    }

    private function config(array $config): array
    {
        return $config + [
            'mode' => 'dev',
            'integrator_key' => 'IK',
            'user_id' => 'USER',
            'private_key' => self::$privateKey,
        ];
    }

    private function request(int $index): RequestInterface
    {
        return $this->history[$index]['request'];
    }

    private function authResponses(): array
    {
        return [
            $this->json(['access_token' => 'TOKEN-1', 'token_type' => 'Bearer', 'expires_in' => 3600]),
            $this->json(['sub' => 'USER', 'accounts' => [
                ['account_id' => 'ACC-OTHER', 'is_default' => 'false', 'base_uri' => 'https://na2.docusign.net'],
                ['account_id' => 'ACC-1', 'is_default' => 'true', 'base_uri' => 'https://demo.docusign.net'],
            ]]),
        ];
    }

    private function json(array $data, int $status = 200): Response
    {
        return new Response($status, ['Content-Type' => 'application/json'], json_encode($data));
    }

    private function envelope(string $status, array $signers, array $overrides = []): array
    {
        return $overrides + [
            'envelopeId' => 'ENV-1',
            'status' => $status,
            'emailSubject' => 'Affaire n°12',
            'createdDateTime' => '2026-11-12T09:00:00.0000000Z',
            'recipients' => ['signers' => $signers],
            'customFields' => ['textCustomFields' => [
                ['fieldId' => '1', 'name' => 'customId', 'value' => '77'],
                ['fieldId' => '2', 'name' => 'returnUrl', 'value' => 'https://wime.test/associe?r=signature'],
            ]],
        ];
    }

    private function recipient(int $id, string $status, string $firstname = 'Jean', string $lastname = 'DUPONT', array $overrides = []): array
    {
        return $overrides + [
            'recipientId' => (string) $id,
            'recipientIdGuid' => 'GUID-'.$id,
            'clientUserId' => (string) $id,
            'routingOrder' => (string) $id,
            'name' => $firstname.' '.$lastname,
            'email' => 'signer'.$id.'@example.com',
            'status' => $status,
            'customFields' => ['firstname:'.$firstname, 'lastname:'.$lastname],
            'identityVerification' => [
                'workflowId' => 'WF-PHONE',
                'inputOptions' => [[
                    'name' => 'phone_number_list',
                    'valueType' => 'PhoneNumberList',
                    'phoneNumberList' => [['countryCode' => '33', 'number' => '612345678']],
                ]],
            ],
        ];
    }

    private function signer(int $id, string $firstname, ?string $phone): Signer
    {
        $signer = new Signer();
        $signer->setId($id);
        $signer->setFirstname($firstname);
        $signer->setLastname('DE LA TOUR');
        $signer->setEmail('signer'.$id.'@example.com');
        if(!is_null($phone)){
            $signer->setPhone($phone);
        }

        return $signer;
    }

    /**
     * @param  array<Signer>|null  $signers
     */
    private function scenario(?array $signers = null): Scenario
    {
        // Scenario::setSigners() appends: build the list once
        $signers ??= [
            $this->signer(1, 'Jean Pierre', '+33612345678'),
            // A national number, read with the default region
            $this->signer(2, 'Marie', '06 98 76 54 32'),
        ];

        $document = new Document();
        $document->setId(1);
        $document->setName('Bulletin de souscription');
        $document->setFilepath($this->pdf());
        $document->setMetadata(['contractId' => 42]);

        $mainSignature = new Signature();
        $mainSignature->setSignerId(1);
        $mainSignature->setDocumentId(1);
        $mainSignature->setLabel('Souscripteur');
        $mainSignature->setPage(2);
        $mainSignature->setLocation([100, 200, 150, 60]);
        $mainSignature->setMention('Lu et approuvé');

        $coSignature = new Signature();
        $coSignature->setSignerId(2);
        $coSignature->setDocumentId(1);
        $coSignature->setLabel('Co-souscripteur');
        $coSignature->setPage(2);
        $coSignature->setLocation([300, 200, 150, 60]);

        $scenario = new Scenario();
        $scenario->setTitle('Affaire n°12');
        $scenario->setCustomId('77');
        $scenario->setSigners($signers);
        $scenario->setDocuments([$document]);
        $scenario->setSignatures([$mainSignature, $coSignature]);
        $scenario->setStatusUrl('https://wime.test/webhook/docusign');
        $scenario->setSuccessUrl('https://wime.test/associe?r=signature');
        $scenario->setLang('fr');
        $scenario->setInvitationMode(Scenario::INVITATION_MODE_CHAIN);

        return $scenario;
    }

    private function pdf(): string
    {
        return __DIR__.'/Files/document1.pdf';
    }
}
