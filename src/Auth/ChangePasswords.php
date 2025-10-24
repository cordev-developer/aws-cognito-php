<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) EllaiSys <support@ellaisys.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ellaisys\Cognito\Auth;

use Illuminate\Contracts\View\Factory;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\View;
use Illuminate\Support\Facades\App;

use Ellaisys\Cognito\AwsCognitoClient;
use Ellaisys\Cognito\AwsCognitoUserPool;

use Exception;
use Illuminate\Validation\ValidationException;
use Ellaisys\Cognito\Exceptions\NoTokenException;
use Ellaisys\Cognito\Exceptions\InvalidUserException;
use Ellaisys\Cognito\Exceptions\InvalidUserFieldException;
use Ellaisys\Cognito\Exceptions\AwsCognitoException;

trait ChangePasswords
{
    /**
     * private variable for password policy
     */
    private $passwordPolicy = null;

    /**
     * Passed params
     */
    private string $paramUsername = 'email';
    private string $paramPasswordOld = 'password';
    private string $paramPasswordNew = 'new_password';
    

    /**
     * Change the given user's password.
     *
     * @param Collection|Request $request
     * @param  string  $paramUsername (optional)
     * @param  string  $passwordOld (optional)
     * @param  string  $passwordNew (optional)
     *
     * @return string
     */
    public function reset(Collection|Request $request, string $paramUsername='email', string $passwordOld='password', string $passwordNew='new_password'): string
    {
        try {

            //Assign params
            $this->paramUsername = $paramUsername;
            $this->paramPasswordOld = $passwordOld;
            $this->paramPasswordNew = $passwordNew;

            try {
                // Request to Collection
                if ($request instanceof Request) {
                    $request = collect($request->all());
                } //End if

                // To assure is a Collection
                if (!($request instanceof Collection)) {
                    $request = collect($request);
                }

                // Obtaining cognito password policy
                $this->passwordPolicy = App::make(AwsCognitoUserPool::class)->getPasswordPolicy(true);
                // Rules definition
                $rules = [
                    $this->paramUsername => ['required'],
                    $this->paramPasswordOld   => ['required', 'regex:' . $this->passwordPolicy['regex']],
                    $this->paramPasswordNew   => ['required', 'confirmed', 'regex:' . $this->passwordPolicy['regex']],
                ];

                // Custom messages
                $messages = [
                    "$this->paramPasswordOld.regex" => 'Existing password must contain at least: ' . $this->passwordPolicy['message'],
                    "$this->paramPasswordNew.regex" => 'New password must contain at least: ' . $this->passwordPolicy['message'],
                    "$this->paramPasswordNew.confirmed" => 'The new password confirmation does not match.',
                ];

                // Create validator
                $validator = Validator::make($request->toArray(), $rules, $messages);

                // Here we can write our logic
                // ...

            } catch (\Exception $e) {
//                \Log::error($e->getMessage());
                throw $e;
            }

            $request = $request->toArray();

            //Create AWS Cognito Client
            $client = App::make(AwsCognitoClient::class);
            //Get User Data sending the user email or username
            $user = $client->getUser($request[$paramUsername]);

            if (empty($user)) {
                throw new InvalidUserException('cognito.validation.reset_required.invalid_user');
            } //End if

            // Check the user 'email' attribute
            $email = null;
            if (isset($user['UserAttributes'])) {
                foreach ($user['UserAttributes'] as $attribute) {
                    if ($attribute['Name'] === 'email') {
                        $email = $attribute['Value'];
                    }
                }
            }

            $request[$paramUsername] = $email;
            $request = collect($request);

            // Action based on User Status
            switch ($user['UserStatus']) {
                case AwsCognitoClient::FORCE_CHANGE_PASSWORD:
                    $response = $this->forceNewPassword($client, $request, $paramUsername, $passwordOld, $passwordNew);
                    break;

                case AwsCognitoClient::RESET_REQUIRED_PASSWORD:
                    throw new AwsCognitoException('cognito.validation.reset_required.invalid_request');
                    break;

                default:
                    $response = $this->changePassword($client, $request, $paramUsername, $passwordOld, $passwordNew);
                    break;
            } //End switch

            return $response;
        } catch (Exception $e) {
            Log::error($e->getMessage());
            throw $e;
        } //Try Catch ends
    } //Function ends


    /**
     * If a user is being forced to set a new password for the first time follow that flow instead.
     *
     * @param AwsCognitoClient $client
     * @param Collection $request
     * @param  string  $paramUsername
     * @param  string  $passwordOld
     * @param  string  $passwordNew
     *
     * @return string
     */
    private function forceNewPassword(AwsCognitoClient $client, Collection $request, string $paramUsername, string $passwordOld, string $passwordNew): string
    {
        //Authenticate user
        $login = $client->authenticate($request[$paramUsername], $request[$passwordOld]);

        return $client->confirmPassword($request[$paramUsername], $request[$passwordNew], $login->get('Session'));
    } //Function ends


    /**
     * If a user is being forced to set a new password for the first time follow that flow instead.
     *
     * @param AwsCognitoClient $client
     * @param Collection $request
     * @param  string  $paramUsername
     * @param  string  $passwordOld
     * @param  string  $passwordNew
     *
     * @return string
     */
    private function changePassword(AwsCognitoClient $client, Collection $request, string $paramUsername, string $passwordOld, string $passwordNew): string
    {
        //Authenticate user
        $cognitoUser = $client->authenticate($request[$paramUsername], $request[$passwordOld]);
        $accessToken = $cognitoUser['AuthenticationResult']['AccessToken'];

        if (empty($accessToken)) {
            throw new NoTokenException('cognito.validation.reset_required.no_token');
        } //End if

        return $client->changePassword($accessToken, $request[$passwordOld], $request[$passwordNew]);
    } //Function ends


    /**
     * Display the password reset view for the given token.
     *
     * If no token is present, display the link request form.
     *
     * @param Request $request
     * @param  string|null  $token
     * @return \Illuminate\Contracts\View\View
     */
    public function showChangePasswordForm(Request $request, $token = null): \Illuminate\Contracts\View\View
    {
        // Use Facade View::make() instead view()
        return View::make('vendor.ellaisys.aws-cognito.reset-password')
            ->with([
                'token' => $token,
                $this->paramUsername => $request->email
            ]);
    } //Function ends


    /**
     * Get the password reset validation rules.
     *
     * @return array
     * @throws Exception
     */
    protected function rules(): array
    {
        try {
            return [
                $this->paramUsername => 'required|email',
                $this->paramPasswordOld => 'required|regex:'.$this->passwordPolicy['regex'],
                $this->paramPasswordNew => 'required|confirmed|regex:'.$this->passwordPolicy['regex'],
            ];
        } catch (Exception $e) {
            throw $e;
        } //End try
    } //Function ends

} //Trait ends
