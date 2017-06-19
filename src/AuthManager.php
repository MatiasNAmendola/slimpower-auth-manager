<?php

/**
 * Authentication Manager for SlimPower Framework
 *
 * PHP version 5.3
 *
 * @category    Authentication
 * @package     SlimPower
 * @subpackage  AuthenticationManager
 * @author      Matias Nahuel Améndola <soporte.esolutions@gmail.com>
 * @link        https://github.com/MatiasNAmendola/slimpower-auth-manager
 * @license     http://www.opensource.org/licenses/mit-license.html MIT License
 * @copyright   2016
 * 
 * MIT LICENSE
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

namespace SlimPower\AuthenticationManager;

use SlimPower\Slim\Libs\Net;
use SlimPower\Authentication\Interfaces\LoginAuthenticatorInterface;
use SlimPower\Authentication\Interfaces\TokenAuthenticatorInterface;
use SlimPower\Authentication\Interfaces\ErrorInterface;
use SlimPower\JwtAuthentication\JwtAuthentication;
use SlimPower\JWT\JwtGenerator;
use SlimPower\HttpBasicAuthentication\HttpBasicAuthentication;

abstract class AuthManager implements Interfaces\ManagerInterface {

    private static $instance;

    /**
     * SlimPower instance
     * @var \SlimPower\Slim\Slim
     */
    protected $app = null;

    /**
     * Application's security scope
     * @var boolean 
     */
    protected $appSecure = false;

    /**
     * Token relaxed
     * @var array 
     */
    protected $tokenRelaxed = array();

    /**
     * Token secret
     * @var string 
     */
    protected $tokenSecret = '';

    /**
     * Token validity
     * @var int 
     */
    protected $tokenValidity = 0;

    /**
     * Insecure paths (without interaction token scope)
     * @var array 
     */
    protected $insecurePaths = array();

    /**
     * Authenticator handler for Login
     * @var \SlimPower\Authentication\Interfaces\AuthenticatorInterface
     */
    protected $authLogin = null;

    /**
     * Authenticator handler for Token
     * @var \SlimPower\Authentication\Interfaces\AuthenticatorInterface
     */
    protected $authToken = null;

    /**
     * Error handler
     * @var \SlimPower\Authentication\Interfaces\ErrorInterface 
     */
    protected $error = null;

    /**
     * Hybrid paths with posibility to access with authentication or not.
     * @var array 
     */
    protected $warningPaths = array();

    /**
     * Get AuthManager instance
     * @param \SlimPower\Slim\Slim $app SlimPower instance
     * @param \SlimPower\Authentication\Interfaces\LoginAuthenticatorInterface $authLogin Authenticator handler for Login
     * @param \SlimPower\Authentication\Interfaces\TokenAuthenticatorInterface $authToken Authenticator handler for Token
     * @param \SlimPower\Authentication\Interfaces\ErrorInterface $error Error handler
     * @return \SlimPower\AuthenticationManager\AuthManager
     */
    public static function getInstance(\SlimPower\Slim\Slim $app, LoginAuthenticatorInterface $authLogin, TokenAuthenticatorInterface $authToken, ErrorInterface $error) {
        if (!isset(self::$instance)) {
            $object = get_called_class();
            self::$instance = new $object($app, $authLogin, $authToken, $error);
        }

        return self::$instance;
    }

    /**
     * Constructor
     * @param \SlimPower\Slim\Slim $app SlimPower instance
     * @param \SlimPower\Authentication\Interfaces\LoginAuthenticatorInterface $authLogin Authenticator handler for login
     * @param \SlimPower\Authentication\Interfaces\TokenAuthenticatorInterface $authToken Authenticator handler for Token
     * @param ErrorInterface $error Error handler
     */
    protected function __construct(\SlimPower\Slim\Slim $app, LoginAuthenticatorInterface $authLogin, TokenAuthenticatorInterface $authToken, ErrorInterface $error) {
        $this->app = $app;
        $this->setAppSecure();
        $this->authLogin = $authLogin;
        $this->authToken = $authToken;
        $this->error = $error;
        $this->buildTokenRelaxed();
        $this->buildInsecurePaths();

        $class = get_class($this); //get_called_class();     

        $app->container->singleton('authManager', function () use ($app, $authLogin, $authToken, $error, $class) {
            return $class::getInstance($app, $authLogin, $authToken, $error);
        });
    }

    /**
     * Set application's security scope
     */
    private function setAppSecure() {
        $this->appSecure = Net::isSecure();
    }

    /**
     * Get application's security scope
     * @return boolean
     */
    public function getAppSecure() {
        return $this->appSecure;
    }

    /**
     * Build token relaxed
     */
    private function buildTokenRelaxed() {
        $localhost = Net::getLocalHost();
        $localIP = Net::getLocalIP();

        $this->tokenRelaxed = array($localhost, $localIP);
    }

    /**
     * Add token relaxed
     * @param array $tokenRelaxed Token relaxed
     */
    public function addTokenRelaxed(array $tokenRelaxed = array()) {
        $relaxed = $this->tokenRelaxed;

        if (!empty($tokenRelaxed) && is_array($tokenRelaxed)) {
            $relaxed = array_merge($relaxed, $tokenRelaxed);
        }

        $this->tokenRelaxed = $relaxed;
    }

    /**
     * Get token relaxed
     * @return array
     */
    public function getTokenRelaxed() {
        return $this->tokenRelaxed;
    }

    /**
     * Build insecure paths (without interaction token scope)
     */
    private function buildInsecurePaths() {
        // Auth: Custom Authentication, Token: HTTP Basic Authentication.
        $this->insecurePaths = array("/auth", "/token");
    }

    /**
     * Add insecure paths (without interaction token scope)
     * @param array $insecurePaths Insecure paths
     */
    public function addInsecurePaths(array $insecurePaths = array()) {
        $paths = $this->insecurePaths;

        if (!empty($insecurePaths) && is_array($insecurePaths)) {
            $paths = array_merge($paths, $insecurePaths);
        }

        $this->insecurePaths = $paths;
    }

    /**
     * Get insecure paths (without interaction token scope)
     * @return array
     */
    public function getInsecurePaths() {
        return $this->insecurePaths;
    }

    /**
     * Set hybrid paths with posibility to access with authentication or not.
     * @param array $warningPaths Warning paths
     */
    public function setWarningPaths(array $warningPaths) {
        $this->warningPaths = $warningPaths;
    }

    /**
     * Get hybrid paths with posibility to access with authentication or not.
     * @return array
     */
    public function getWarningPaths() {
        return $this->warningPaths;
    }

    /**
     * Get token secret
     * @return string
     */
    public function getTokenSecret() {
        return $this->tokenSecret;
    }

    /**
     * Set token secret
     * @param string $tokenSecret Token secret
     */
    public function setTokenSecret($tokenSecret) {
        $this->tokenSecret = $tokenSecret;
    }

    /**
     * Get token validity
     * @return int
     */
    public function getTokenValidity() {
        return $this->tokenValidity;
    }

    /**
     * Set token validity
     * @param int $tokenValidity Token validity
     */
    public function setTokenValidity($tokenValidity) {
        $this->tokenValidity = $tokenValidity;
    }

    /**
     * Start authentication security
     */
    public function start() {
        $this->addHttpBasicAuthentication();
        $this->addJwtAuthentication();
    }

    /**
     * Add http basic authentication
     */
    private function addHttpBasicAuthentication() {
        $config = $this->getHttpBasicAuthenticationConfig();

        $app = $this->app;
        $app->add(new HttpBasicAuthentication($config));

        $app->get('/token(/)', function () use ($app) {
            /* Everything ok, generate token! */
            $app->authManager->generateToken();
        });
    }

    /**
     * Get Http Basic Authentication config.
     * @return array
     */
    private function getHttpBasicAuthenticationConfig() {
        $config = array(
            "path" => "/token",
            "realm" => "Protected",
            "secure" => $this->appSecure,
            "relaxed" => $this->tokenRelaxed,
            //"users"  => array(
            //      "admin" => "demo",
            //),
            "environment" => "REDIRECT_HTTP_AUTHORIZATION",
            "error" => $this->error,
            "authenticator" => $this->authLogin
        );

        return $config;
    }

    /**
     * Add JWT authentication
     */
    private function addJwtAuthentication() {
        $config = $this->getJwtAuthenticationConfig();

        $app = $this->app;
        $app->add(new JwtAuthentication($config));

        $app->get('/auth(/)', function () use ($app) {
            $app->authManager->getAuthorization();
        });
    }

    /**
     * Get JWT Authentication config.
     * @return array
     */
    private function getJwtAuthenticationConfig() {
        $cPathRule = array("path" => "/", "passthrough" => $this->insecurePaths);

        $app = $this->app;

        $callback = function ($options) use ($app) {
            /* Everything ok, add custom property! */
            $app->jwt = $options['decoded'];
        };

        $config = array(
            "path" => "/",
            "secret" => $this->tokenSecret,
            "secure" => $this->appSecure,
            "warningPaths" => $this->warningPaths,
            "rules" => array(
                new \SlimPower\Authentication\Callables\RequestPathRule($cPathRule)
            ),
            "relaxed" => $this->tokenRelaxed,
            "callback" => $callback,
            "error" => $this->error,
            "authenticator" => $this->authToken
        );

        return $config;
    }

    /**
     * Get authorization
     */
    public function getAuthorization() {
        $loginData = $this->getLoginData();

        $error = new \SlimPower\Authentication\Error();
        $error->setCode(1);
        $error->setDescription("Incorrect User.");

        $ie = $this->error;
        $ia = $this->authLogin;

        if (!$loginData) {
            $ie($error);
            return;
        }

        if (!$ia($loginData)) {
            $error = $this->authLogin->getError();
            $ie($error);
        } else {
            /* Everything ok, generate token! */
            $this->generateToken();
        }
    }

    public function generateToken() {
        $data = $this->app->userData;
        $jwtGenerator = new JwtGenerator($this->app);
        $jwtGenerator->setTokenSecret($this->tokenSecret);
        $jwtGenerator->setTokenValidity($this->tokenValidity);
        $token = $jwtGenerator->generateToken($data);
        /* Everything ok, add custom property! */
        $this->app->token = $token;
        $this->sendCredential($token);
    }

    /**
     * Get login data
     * @return array Login data
     */
    abstract protected function getLoginData();

    abstract protected function sendCredential($token);
}
