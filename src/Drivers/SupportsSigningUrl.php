<?php

namespace Helori\PhpSign\Drivers;


/**
 * A driver whose signing URLs expire too soon to be stored or sent by email.
 * The application asks for a URL right before redirecting the signer.
 */
interface SupportsSigningUrl
{
    /**
     * Create a URL that opens the signing page of one signer
     *
     * @param  string  $transactionId
     * @param  int  $signerId  the signer's id in the scenario
     * @param  string|null  $returnUrl  where the provider sends the signer back; null reuses the scenario's success URL
     * @return string
     */
    public function createSigningUrl(string $transactionId, int $signerId, ?string $returnUrl = null): string;
}
