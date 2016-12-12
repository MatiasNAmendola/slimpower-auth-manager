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

namespace SlimPower\AuthenticationManager\Interfaces;

interface ManagerInterface {

    public function start();

    /**
     * Get instance
     * @param \SlimPower\Slim\Slim $app SlimPower Instance
     * @param \SlimPower\Authentication\Interfaces\AuthenticatorInterface $authenticator Authenticator
     */
    public static function getInstance(\SlimPower\Slim\Slim $app, \SlimPower\Authentication\Interfaces\AuthenticatorInterface $authenticator);

    public function getAuthorization();

    public function getAppSecure();

    public function addTokenRelaxed(array $tokenRelaxed = array());

    public function getTokenRelaxed();

    public function addInsecurePaths(array $insecurePaths = array());

    public function getInsecurePaths();

    public function setTokenSecret($tokenSecret);

    public function getTokenSecret();

    public function setTokenValidity($tokenValidity);

    public function getTokenValidity();

    public function generateToken();
}
