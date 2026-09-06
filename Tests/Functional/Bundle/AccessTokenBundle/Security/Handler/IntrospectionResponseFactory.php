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

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
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

        if ('SIGNED_ACCESS_TOKEN' === ($body['token'] ?? null)) {
            return self::signedResponse($options['normalized_headers']['accept'] ?? []);
        }

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

    /**
     * Answers the RFC 9701 signed introspection response, or plain JSON when the request did not
     * announce that media type, which is what an authorization server unable to sign would do.
     *
     * @param list<string> $accept
     */
    private static function signedResponse(array $accept): MockResponse
    {
        $members = [
            'active' => true,
            'sub' => 'dunglas',
            'iss' => 'https://authorization-server.example.com/',
            'aud' => ['https://protected.example.net/resource'],
            'exp' => time() + 3600,
        ];

        if (!str_contains(implode(',', $accept), 'application/token-introspection+jwt')) {
            return new JsonMockResponse($members);
        }

        $jws = (new CompactSerializer())->serialize((new JWSBuilder(new AlgorithmManager([new ES256()])))
            ->withPayload(json_encode([
                'iss' => 'https://authorization-server.example.com/',
                'aud' => 'https://protected.example.net/resource',
                'iat' => time(),
                'token_introspection' => $members,
            ], \JSON_THROW_ON_ERROR))
            ->addSignature(new JWK([
                'kty' => 'EC',
                'crv' => 'P-256',
                'd' => 'iA_TV2zvftni_9aFAQwFO_9aypfJFCSpcCyevDvz220',
                'x' => '0QEAsI1wGI-dmYatdUZoWSRWggLEpyzopuhwk-YUnA4',
                'y' => 'KYl-qyZ26HobuYwlQh-r0iHX61thfP82qqEku7i0woo',
            ]), ['alg' => 'ES256', 'typ' => 'token-introspection+jwt'])
            ->build()
        );

        return new MockResponse($jws, ['response_headers' => ['Content-Type' => 'application/token-introspection+jwt']]);
    }
}
