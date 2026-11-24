<?php

namespace Helori\PhpSign\Drivers;


/**
 * A driver that issues a proof of signature (certificate of completion)
 * separate from the signed documents.
 */
interface SupportsCertificate
{
    /**
     * Get the PDF content of the transaction's proof of signature
     *
     * @param  string  $transactionId
     * @return string
     */
    public function getCertificate(string $transactionId): string;
}
