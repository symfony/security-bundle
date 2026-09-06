<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Bundle\SecurityBundle\DependencyInjection\Security\AccessToken;

use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\LogicException;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Contracts\Cache\CacheInterface;

/**
 * Configures a token handler for an OAuth2 Token Introspection endpoint.
 *
 * Where the authorization server lives and how this resource server authenticates there is the
 * business of the HTTP client the "http_client" option names, not of the firewall: a scoped client
 * declares the introspection endpoint as its "base_uri" and the credentials RFC 7662 §2.1 requires
 * the endpoint to demand as its "auth_basic". Those credentials are sent as given, where the
 * "client_secret_basic" of RFC 6749 §2.3.1 form-urlencodes both halves, so a client id or a secret
 * holding a colon, a plus, a space or a non-ASCII byte must be encoded before it is passed. What is
 * configured here is only what the firewall itself needs, namely what the response is confronted
 * with.
 *
 * @internal
 */
class OAuth2TokenHandlerFactory implements TokenHandlerFactoryInterface
{
    public function create(ContainerBuilder $container, string $id, array|string $config): void
    {
        $tokenHandlerDefinition = $container->setDefinition($id, new ChildDefinition('security.access_token_handler.oauth2'))
            ->replaceArgument(2, $config['audience'])
            ->replaceArgument(3, $config['issuer'])
            ->replaceArgument(4, $config['claim'])
            ->replaceArgument(6, $config['allowed_time_drift'])
        ;

        if (isset($config['http_client'])) {
            $tokenHandlerDefinition->replaceArgument(0, new Reference($config['http_client']));
        }

        if (isset($config['cache'])) {
            if (!ContainerBuilder::willBeAvailable('symfony/cache', CacheInterface::class, ['symfony/security-bundle'])) {
                throw new LogicException('You cannot cache the introspection responses of the "oauth2" token handler since the Cache component is not installed. Try running "composer require symfony/cache".');
            }

            $tokenHandlerDefinition->addMethodCall('enableCache', [
                new Reference($config['cache']['id']),
                "$id.introspection.",
                $config['cache']['ttl'],
            ]);
        }
    }

    public function getKey(): string
    {
        return 'oauth2';
    }

    public function addConfiguration(NodeBuilder $node): void
    {
        $node
            ->arrayNode($this->getKey())
                ->beforeNormalization()
                    ->ifString()
                    ->then(static fn ($v) => ['http_client' => $v])
                ->end()
                ->children()
                    ->scalarNode('http_client')
                        ->info('HttpClient service id the introspection endpoint is called with. Declare it as a scoped client whose "base_uri" is the introspection endpoint of your authorization server and whose "auth_basic" holds the credentials it authenticates with. Those are sent as given, where the "client_secret_basic" of RFC 6749 §2.3.1 form-urlencodes both halves, so encode a client id or a secret holding a colon, a plus or a space yourself.')
                        ->cannotBeEmpty()
                    ->end()
                    ->arrayNode('audience')
                        ->info('Identifiers of this resource server, one of which the "aud" of the introspection response must name. A single identifier may be given as a string.')
                        ->acceptAndWrap(['string'])
                        ->scalarPrototype()->cannotBeEmpty()->end()
                    ->end()
                    ->scalarNode('issuer')
                        ->info('Identifier of the authorization server, checked against the "iss" of the introspection response.')
                        ->defaultNull()
                        ->cannotBeEmpty()
                    ->end()
                    ->scalarNode('claim')
                        ->info('Claim which contains the user identifier (e.g.: sub, username, email...). Defaults to "sub", falling back to "username".')
                        ->defaultNull()
                        ->cannotBeEmpty()
                    ->end()
                    ->integerNode('allowed_time_drift')
                        ->info('Allowed time drift in seconds when validating the "iat", "nbf" and "exp" of the introspection response.')
                        ->defaultValue(0)
                        ->min(0)
                    ->end()
                    ->arrayNode('cache')
                        ->info('Cache the introspection responses of active tokens, never beyond their "exp".')
                        ->children()
                            ->scalarNode('id')
                                ->info('Cache service id to use to cache the introspection responses.')
                                ->isRequired()
                                ->cannotBeEmpty()
                            ->end()
                            ->integerNode('ttl')
                                ->info('Maximum lifetime in seconds of a cached introspection response. The shorter it is, the sooner a revoked token stops being accepted.')
                                ->defaultValue(60)
                                ->min(1)
                            ->end()
                        ->end()
                    ->end()
                ->end()
            ->end()
        ;
    }
}
