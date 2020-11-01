<?php
/**
 * Authentication Plugin that will use a Facebook Graph API access token
 * as a credential.  The facebook access token should be provided in the $_POST
 * parameters with name 'facebooktoken'.  It can be included with any request
 * even AJAX requests to automatically login, without prompting or redirecting.
 * 
 * The users table should include a column named facebook_id which stores the facebook
 * ID of the user.  This column can have an alternate name but that name would need to be
 * specified in the 'facebook_id_column' directive of the [_auth] section of the conf.ini file.
 * 
 * If you want a user account to be automatically created the first time the user 
 * logs in with a valid access token, you can add facebook.autocreate=1 to the [_auth]
 * section of the conf.ini file.  In such cases it will autopopulate the facebook_id
 * column, and the email column (if the user has an email address in facebook).  
 * 
 * If facebook.autocreate=1, then two hooks will be called:
 *    1. beforeAddFacebookUser(string $accessToken, Dataface_Record $user)
 *    2. afterAddFacebookUser(string $accessToken, Dataface_Record $user)
 * 
 * These will give you an opportunity to customize the user record/set its role,
 * etc...
 * 
 * This plugin is best used as a pre_auth_type since it doesn't work with a normal 
 * login prompt (yet).  Enable it by adding pre_auth_types=facebook to the [_auth]
 * section of the conf.ini file.
 */
class dataface_modules_oauth_token {
    
    
    private $loggedInUser;
    private $serviceName;

    public function authenticate() {
        $app =& Dataface_Application::getInstance();
        $app->startSession();
        foreach (array_keys($app->_conf) as $key) {
            if (strpos($key, 'oauth_') === 0) {
                $serviceName = substr($key, 6);
                $this->serviceName = $serviceName;
                $res = $this->authenticate1();
                
            }
        }
        return PEAR::raiseError("Not handled", DATAFACE_E_REQUEST_NOT_HANDLED);
    }
    
    public function authenticate1() {
        $auth =& Dataface_AuthenticationTool::getInstance();
        $app = Dataface_Application::getInstance();
        //$mod =& Dataface_ModuleTool::getInstance()->loadModule('modules_oauth1_twitter');
        $delegate =& $app->getDelegate();
        $mod =& Dataface_ModuleTool::getInstance()->loadModule('modules_oauth');
		$oauth = $mod;
        $accessToken = null;
        $accessTokenSecret = null;
        $serviceName = $this->serviceName;
        $ucServiceName = strtoupper($serviceName);
        
        if (isset($_SERVER['HTTP_XF_'.$ucServiceName.'_OAUTH_TOKEN'])) {
            $accessToken = $_SERVER['HTTP_XF_'.$ucServiceName.'_OAUTH_TOKEN'];
        } else if (isset($_REQUEST[$ucServiceName.'_OAUTH_TOKEN'])) {
            $accessToken = $_REQUEST[$ucServiceName.'_OAUTH_TOKEN'];
        }
        if (isset($_SERVER['HTTP_XF_'.$ucServiceName.'_OAUTH_TOKEN_SECRET'])) {
            $accessTokenSecret = $_SERVER['HTTP_XF_'.$ucServiceName.'_OAUTH_TOKEN_SECRET'];
        } else if (isset($_REQUEST[$ucServiceName.'_OAUTH_TOKEN'])) {
            $accessTokenSecret = $_REQUEST[$ucServiceName.'_OAUTH_TOKEN_SECRET'];
        }
        
        
        $existingOauthToken = $mod->getOauthToken($serviceName);
        $existingOauthTokenSecret = $mod->getOauthTokenSecret($serviceName);
        
        if (isset($accessToken) and isset($accessTokenSecret) and 
                $accessToken !=  $existingOauthToken) {
            $oauth->setOauthToken($serviceName, $accessToken, $accessTokenSecret);
            $userData = $oauth->fetchUserData($serviceName);
            //$userData = $mod->fetchUserData($serviceName);
            if (!isset($userData)) {
                error_log("$serviceName login failed.  Could not fetch userData");
                return PEAR::raiseError("Not handled", DATAFACE_E_REQUEST_NOT_HANDLED);
            }
                
            $serviceUserId = $mod->extractServiceUserIdFromUserData($serviceName, $userData);
            if (!isset($serviceUserId)) {
                error_log("$serviceName login failed because failed to extract user Id from user data");
                return PEAR::raiseError("Not handled", DATAFACE_E_REQUEST_NOT_HANDLED);
            }
            
            
            $oauth->setServiceUserId($serviceName, $serviceUserId);
            
            $usersTable = Dataface_Table::loadTable($auth->usersTable);
            $idColumn = $mod->getServiceUserIdColumn($serviceName);
            $serviceUserId = $mod->getServiceUserId($serviceName);
            
            
            if ($auth->isLoggedIn()) {
                // User is already logged in.  We'll try to link their twitter account
                // to their user account.
                $user = $auth->getLoggedInUser();
                
                if ($delegate and method_exists($delegate, 'oauth_link_profile')) {
                    $res = $delegate->oauth_link_profile($serviceName, $auth->getLoggedInUser());
                    if (PEAR::isError($res)) {
                        error_log('Failed to link profile: '.$res->getMessage());
                        
                    } else {
                        $oauth->setOauthToken($serviceName, $accessToken, $accessTokenSecret, true);
                    }
                    return PEAR::raiseError("Not handled", DATAFACE_E_REQUEST_NOT_HANDLED);;
                }
                if (isset($idColumn) and isset($serviceUserId)) {
                    if (!$user->val($idColumn)) {
                        $user->setValue($idColumn, $serviceUserId);
                        $saveResult = $user->save();
                        if (PEAR::isError($saveResult)) {
                            error_log("Failed to save user account to connect with service ".$serviceName);
                            error_log($saveResult->getMessage());
                            
                        } else {
                            $oauth->setOauthToken($accessToken, $accessTokenSecret, true);
                        }
                        return PEAR::raiseError("Not handled", DATAFACE_E_REQUEST_NOT_HANDLED);
                    }
                }
            } else {
                // User is not logged in.
                // We'll try to log them in.
                $user = $oauth->getUser($serviceName);
                if (isset($user)) {
                    if ($user and $user->val($auth->usernameColumn)) {
                        $_SESSION['UserName'] = $user->val($auth->usernameColumn);
                        $oauth->setOauthToken($accessToken, $accessTokenSecret, true);
                    } 
                } else {
                    $user = $mod->createUser($serviceName, $userData);
                    if (PEAR::isError($user)) {
                        error_log("Failed to create twitter user ".$user->getMessage());
                        
                    } else if ($user) {
                         $_SESSION['UserName'] = $user->val($auth->usernameColumn);
                         $oauth->setOauthToken($accessToken, $accessTokenSecret, true);
                    }
                }
            }
        }
        
        return PEAR::raiseError("Not handled", DATAFACE_E_REQUEST_NOT_HANDLED);
        
    }
    
    
    public function getLoggedInUser() {
        return $this->loggedInUser;
    }
    
    public function getLoggedInUsername(){
        if ( !@$_SESSION['UserName'] ) return null;
        return @$_SESSION['UserName'];	
    }
}
    