<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Bundle\SecurityBundle\Tests\Functional\Bundle\AccessTokenBundle\Security\Handler;

use Symfony\Component\HttpClient\Response\JsonMockResponse;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * Stands in for the introspection endpoint of an authorization server.
 *
 * It is wired as the "mock_response_factory" of a scoped client, so the request still travels
 * through the real ScopingHttpClient: the URL and the options it records are the ones the scoped
 * client resolved, which is what the token handler relies on to reach the endpoint at all.
 */
final class IntrospectionResponseFactory
{
    /**
     * @var list<array{method: string, url: string, options: array<string, mixed>}>
     */
    public array $requests = [];

    public function __invoke(string $method, string $url, array $options): MockResponse
    {
        $this->requests[] = ['method' => $method, 'url' => $url, 'options' => $options];

        parse_str($options['body'] ?? '', $body);

        if ('FOREIGN_ISSUER_ACCESS_TOKEN' === ($body['token'] ?? null)) {
            return new JsonMockResponse([
                'active' => true,
                'sub' => 'dunglas',
                'iss' => 'https://another-authorization-server.example.com/',
                'aud' => ['https://protected.example.net/resource'],
                'exp' => time() + 3600,
            ]);
        }

        if ('VALID_ACCESS_TOKEN' !== ($body['token'] ?? null)) {
            return new JsonMockResponse(['active' => false]);
        }

        return new JsonMockResponse([
            'active' => true,
            'sub' => 'dunglas',
            'iss' => 'https://authorization-server.example.com/',
            'aud' => ['https://protected.example.net/resource'],
            'exp' => time() + 3600,
        ]);
    }
}
