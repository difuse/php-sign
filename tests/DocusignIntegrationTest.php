<?php

namespace Helori\PhpSign\Test;

use Helori\PhpSign\Drivers\DocusignDriver;
use Helori\PhpSign\Elements\Document;
use Helori\PhpSign\Elements\Requester;
use Helori\PhpSign\Elements\Scenario;
use Helori\PhpSign\Elements\Signature;
use Helori\PhpSign\Elements\Signer;
use Helori\PhpSign\Elements\SignerResult;
use Helori\PhpSign\Elements\Transaction;
use PHPUnit\Framework\TestCase;


/**
 * Runs against the Docusign demo environment. Skipped unless these
 * environment variables are set:
 *
 * - DOCUSIGN_INTEGRATOR_KEY, DOCUSIGN_USER_ID
 * - DOCUSIGN_PRIVATE_KEY_PATH: path of the RSA private key file
 * - DOCUSIGN_TEST_EMAIL, DOCUSIGN_TEST_PHONE: the test signer, who gets the code
 *
 * Optional: DOCUSIGN_ACCOUNT_ID, DOCUSIGN_REDIRECT_URI (prints the consent URL
 * when consent is missing), DOCUSIGN_KEEP_ENVELOPE=1 to leave the envelope
 * open and sign it from the printed URL.
 */
class DocusignIntegrationTest extends TestCase
{
    public function testSignsADocumentOnTheDemoEnvironment(): void
    {
        $missing = array_filter(
            ['DOCUSIGN_INTEGRATOR_KEY', 'DOCUSIGN_USER_ID', 'DOCUSIGN_PRIVATE_KEY_PATH', 'DOCUSIGN_TEST_EMAIL', 'DOCUSIGN_TEST_PHONE'],
            fn (string $name) => (string) getenv($name) === ''
        );

        if(!empty($missing)){
            $this->markTestSkipped('Docusign demo credentials missing: '.implode(', ', $missing));
        }

        $keyPath = (string) getenv('DOCUSIGN_PRIVATE_KEY_PATH');
        $this->assertFileIsReadable($keyPath);

        $requester = new Requester('docusign', [
            'mode' => 'dev',
            'integrator_key' => getenv('DOCUSIGN_INTEGRATOR_KEY'),
            'user_id' => getenv('DOCUSIGN_USER_ID'),
            'private_key' => file_get_contents($keyPath),
            'account_id' => (string) getenv('DOCUSIGN_ACCOUNT_ID'),
            'redirect_uri' => (string) getenv('DOCUSIGN_REDIRECT_URI'),
        ]);

        $transaction = $requester->createTransaction($this->scenario());
        $this->line('Envelope: '.$transaction->getId());

        $this->assertSame(Transaction::STATUS_READY, $transaction->getStatus());
        $this->assertSame(SignerResult::STATUS_READY, $transaction->getSigners()[0]->getStatus());
        $this->assertNotNull($transaction->getExpireAt());

        $driver = $requester->getDriver();
        $this->assertInstanceOf(DocusignDriver::class, $driver);
        $this->line('Signing URL (5 minutes, once): '.$driver->createSigningUrl($transaction->getId(), 1));

        if(getenv('DOCUSIGN_KEEP_ENVELOPE') === '1'){
            $this->line('Envelope kept open: sign it, then read it again with getTransaction()');
            return;
        }

        $canceled = $requester->cancelTransaction($transaction->getId());
        $this->assertSame(Transaction::STATUS_CANCELED, $canceled->getStatus());
    }

    private function scenario(): Scenario
    {
        $signer = new Signer();
        $signer->setId(1);
        $signer->setFirstname('Test');
        $signer->setLastname('PHP-SIGN');
        $signer->setEmail((string) getenv('DOCUSIGN_TEST_EMAIL'));
        $signer->setPhone((string) getenv('DOCUSIGN_TEST_PHONE'));

        $document = new Document();
        $document->setId(1);
        $document->setName('Document de test');
        $document->setFilepath(__DIR__.'/Files/document1.pdf');
        $document->setMetadata(['contractId' => 1]);

        // Bottom-right of page 1, in PDF points from the bottom-left corner
        $signature = new Signature();
        $signature->setSignerId(1);
        $signature->setDocumentId(1);
        $signature->setLabel('Signataire');
        $signature->setPage(1);
        $signature->setLocation([350, 100, 180, 60]);
        $signature->setMention('Lu et approuvé');

        $scenario = new Scenario();
        $scenario->setTitle('[TEST] php-sign Docusign');
        $scenario->setCustomId('php-sign-test');
        $scenario->setSigners([$signer]);
        $scenario->setDocuments([$document]);
        $scenario->setSignatures([$signature]);
        $scenario->setSuccessUrl('https://example.com/return');
        $scenario->setLang('fr');
        $scenario->setInvitationMode(Scenario::INVITATION_MODE_CHAIN);

        return $scenario;
    }

    private function line(string $text): void
    {
        fwrite(STDERR, PHP_EOL.$text);
    }
}
