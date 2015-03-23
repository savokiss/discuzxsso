<?php

/**
 * This file makes MediaWiki use a SMF user database to
 * authenticate with. This forces users to have a SMF account
 * in order to log into the wiki. This should also force the user to
 * be in a group called wiki.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @package MediaWiki
 * @subpackage Auth_SMF
 * @author Nicholas Dunnaway
 * @copyright 2004-2006 php|uber.leet
 * @license http://www.gnu.org/copyleft/gpl.html
 * @CVS: $Id: Auth_SMF.php,v 1.3 2007/04/05 22:17:56 nkd Exp $
 * @link http://uber.leetphp.com
 * @version $Revision: 1.3 $
 *
 * 
 * @Modified By Hopesoft
 * @link http://www.51ajax.com
 * @2007-11-11
 *
 *
 * @Modified By outcrop
 * @email outcrop@163.com
 * @2008-04-07
 *
 *
 * @Modified By ChaosConst
 * @link  http://www.yglcub.org
 * @email chaosconst@gmail.com
 * @2013-01-27
 *
 *
 * @Modified By savokiss
 * @link  http://savokiss.me
 * @email savokiss@qq.com
 * @2014-01-12
 *
 **/

// error_reporting(E_ALL); // Debug
include './extensions/DiscuzXSSO/config.inc.php';
include './extensions/DiscuzXSSO/uc_client/client.php';
// First check if class has already been defined.
if (!class_exists('AuthPlugin'))
{
	/**
	 * Auth Plugin
	 *
	 */
	require_once './includes/AuthPlugin.php';
}


function uc_login_hook() {
	global $wgUser, $wgRequest, $wgAuth;

	// 因为是hook调用，需要在这里重新输入一些配置，主要是discuz的cookie和数据库,调用的是config.inc.php里面定义的常量
	$_config = array();
	$_config['cookie']['cookiepre'] = COOKIE_PRE;
	$_config['cookie']['cookiedomain'] = COOKIE_DOMAIN;
	$_config['cookie']['cookiepath'] = COOKIE_PATH;
	$_config['security']['authkey'] = SECURITY_AUTHKEY;

	$dbhost=UC_DBHOST;
	$dbuser=UC_DBUSER;
	$dbpw=UC_DBPW;
	$dbname=UC_DBNAME;
	$dz_tablepre=DZ_DBTABLEPRE;
	$uc_tablepre=UC_DBTABLEPRE;

	//读取用户组全局变量
	$gp_limited = GP_LIMITED;
	$gp_normal = GP_NORMAL;
	$gp_admin = GP_ADMIN;

	// 登陆和登出页面不做同步登陆，For a few special pages, don't do anything.
	$title = $wgRequest->getVal( 'title' );
	if ( ( $title == Title::makeName( NS_SPECIAL, 'UserLogout' ) ) ||
			( $title == Title::makeName( NS_SPECIAL, 'UserLogin' ) ) ) {
		return;
	}
	

	// 第一步,获取当前用户的 UID 和 用户名,从discuz的cookie里面解码出来 
	if(substr($_config['cookie']['cookiepath'], 0, 1) != '/') {
		$_config['cookie']['cookiepath']= '/' . $_config['cookie']['cookiepath'];
	}
	$cookiepre =  $_config['cookie']['cookiepre'] . substr(md5($_config['cookie']['cookiepath'] . '|' .  $_config['cookie']['cookiedomain']), 0, 4) . '_';//COOKIE前缀

	$auth = $cookiepre.'auth';//存储用户信息的COOKIE名
	$saltkey = $_COOKIE[ $cookiepre . 'saltkey'];//解密auth用到的key

	$discuz_auth_key = md5($_config['security']['authkey'] . $saltkey);//x2的密钥
	$auth_value = uc_authcode($_COOKIE[$auth],'DECODE',$discuz_auth_key);
	
	
	// 调试:是否取得discuz的uid 
	// echo "<script>window.onunload=function();</script>";
	// echo "<script>alert('config=".$_config['cookie']['cookiepre']."');</script>";
	// echo "<script>alert('cookie=".$_COOKIE[$auth]."');</script>";
	// echo "<script>alert('auth_value=".$auth_value."');</script>";

	$user = User::newFromSession();
	if(!empty($auth_value)) { 
		list($ygclub_password,$ygclub_uid) = explode("\t", $auth_value); 
	} else {
		//无法从cookie取得uid, 猜测是没有登陆discuz, 维基百科同步登出
		$user->doLogout();
		return ;
	}

	// 第二步, 下面要继续登陆，从UID查询用户名

	// Connect to database.
	$connect = mysql_connect($dbhost, $dbuser, $dbpw, true);

	mysql_select_db($dbname,$connect);
	// 请根据数据库编码调整
    mysql_query("set names utf8");

	$result = mysql_query("SELECT uc_m.username,dz_m.groupid FROM ".$uc_tablepre."members uc_m JOIN ".$dz_tablepre."common_member dz_m WHERE uc_m.uid = '".$ygclub_uid."' AND dz_m.uid = '".$ygclub_uid."'");
	if (!$result) {
		return ;
	}
	$row = mysql_fetch_row($result);

	// 得到用户名
	$ygclub_username= $row[0];

	//从dz数据库读出groupid用来判断并加入到wiki的不同group中,dz的group分组详见config.inc.php中配置
	$sa_groupid = $row[1];//下面switch中会用到用来添加删除用户组
		

	// echo "<script>console.log(".$sa_groupid.");</script>";

	// 验证用户名是否已经登陆，已经登陆则退出，否则登出，用discuz的用户替换之
	if ( !$user->isAnon() ) {
		if ( strtolower($user->getName()) == strtolower($wgAuth->getCanonicalName($ygclub_username)) ) {
			return; // Correct user is already logged in.
		} else {
			$user->doLogout(); // Logout mismatched user.
		}
	}

	// Copied from includes/SpecialUserlogin.php
	if ( !isset( $wgCommandLineMode ) && !isset( $_COOKIE[session_name()] ) ) {
		wfSetupSession();
	}


	// 第三步，发送用户名进行登陆
	// If the login form returns NEED_TOKEN try once more with the right token
	$trycount = 0;
	$token = '';
	$errormessage = '';
	do {
		$tryagain = false;
		// Submit a fake login form to authenticate the user.
		// 用户名必须encode，不然会500错误
                $params = new FauxRequest( array(
					'wpName' => $wgAuth->getCanonicalName($ygclub_username),
					'wpPassword' => 'SUMMERBEGIN',
					'wpDomain' => '',
					'wpLoginToken' => $token,
					'wpRemember' => ''
					) );


		// Authenticate user data will automatically create new users.
		$loginForm = new LoginForm( $params );
		$result = $loginForm->authenticateUserData();
		//		echo "<script>alert('wpName=".urlencode($wgAuth->getCanonicalName($ygclub_username))."auth complete:".$result."');</script>";

		switch ( $result ) {
			case LoginForm :: SUCCESS :
				$wgUser->setOption( 'rememberpassword', 1 );
				$wgUser->setCookies();
				// if(in_array($sa_groupid, explode(',',$gp_limited))){//如果用户在dz中在限制级，就添加到限制用户组中,这里的限制用户组是新增的
				// 	$wgUser->addGroup('limited');
				// }else 
				if(in_array($sa_groupid,explode(',',$gp_normal))){//如果用户在dz中是正常级，就添加到普通用户组中
					$wgUser->addGroup('editor');
				}else if(in_array($sa_groupid,explode(',',$gp_admin))){//如果用户在dz中是管理员，就添加到管理员和行政员用户组中
					$wgUser->addGroup('sysop');
					$wgUser->addGroup('bureaucrat');
				}
				break;
			case LoginForm :: NEED_TOKEN:
				$token = $loginForm->getLoginToken();
				$tryagain = ( $trycount == 0 );
				break;
			case LoginForm :: WRONG_TOKEN:
				$errormessage = 'WrongToken';
				break;
			case LoginForm :: NO_NAME :
				$errormessage = 'NoName';
				break;
			case LoginForm :: ILLEGAL :
				$errormessage = 'Illegal';
				break;
			case LoginForm :: WRONG_PLUGIN_PASS :
				$errormessage = 'WrongPluginPass';
				break;
			case LoginForm :: NOT_EXISTS :
				$errormessage = 'NotExists|'.$ygclub_username."|";
				break;
			case LoginForm :: WRONG_PASS :
				$errormessage = 'WrongPass';
				break;
			case LoginForm :: EMPTY_PASS :
				$errormessage = 'EmptyPass';
				break;
			default:
				$errormessage = 'Unknown';
				break;
		}

		if ( $result != LoginForm::SUCCESS && $result != LoginForm::NEED_TOKEN ) {
			error_log( 'Unexpected REMOTE_USER authentication failure. Login Error was:' . $errormessage );
		}
		$trycount++;
	} while ( $tryagain );

	//验证完毕
        return;
}

/**
 * Handles the Authentication with the Discuz database.
 *
 * @package MediaWiki
 * @subpackage Auth_UCenter
 */
class Auth_UCenter extends AuthPlugin
{

	/**
	 * Add a user to the external authentication database.
	 * Return true if successful.
	 *
	 * NOTE: We are not allowed to add users to Discuz from the
	 * wiki so this always returns false.
	 *
	 * @param User $user
	 * @param string $password
	 * @return bool
	 * @access public
	 */
	function addUser( $user, $password )
	{
		return false;
	}

	/**
	 * Can users change their passwords?
	 *
	 * @return bool
	 */
	function allowPasswordChange()
	{
		return true;
	}

	/**
	 * Check if a username+password pair is a valid login.
	 * The name will be normalized to MediaWiki's requirements, so
	 * you might need to munge it (for instance, for lowercase initial
	 * letters).
	 *
	 * @param string $username
	 * @param string $password
	 * @return bool
	 * @access public
	 * @todo Check if the password is being changed when it contains a slash or an escape char.
	 */
	function authenticate($username, $password)
	{
		// Clean $username and force lowercase username.
		$username = htmlentities(strtolower($username), ENT_QUOTES, 'UTF-8');
		$username = str_replace('&#039;', '\\\'', $username); // Allow apostrophes (Escape them though)
		//调用client的uc_user_login判断用户密码，由于MediaWiki为utf8编码，请自行判断中文ID的编码

		//用户名打出来调试一下
        // echo "<script>alert('username(".$username.")auth passed!');</script>";

		//如果来自同步登陆则通过认证
		if ($password == "SUMMERBEGIN") return true;
		
		//如果来自其他方式则调用UCenter api验证登陆是否有效
		list($uid, $username1, $password, $email) = uc_user_login(iconv("UTF-8", "UTF-8", $username), $password);

		if ($uid > 0 ) {
			uc_user_synlogin($uid);
			return true;
		}

		return false;
	}

	/**
	 * Return true if the wiki should create a new local account automatically
	 * when asked to login a user who doesn't exist locally but does in the
	 * external auth database.
	 *
	 * If you don't automatically create accounts, you must still create
	 * accounts in some way. It's not possible to authenticate without
	 * a local account.
	 *
	 * This is just a question, and shouldn't perform any actions.
	 *
	 * NOTE: I have set this to true to allow the wiki to create accounts.
	 *       Without an accout in the wiki database a user will never be
	 *       able to login and use the wiki. I think the password does not
	 *       matter as long as authenticate() returns true.
	 *
	 * @return bool
	 * @access public
	 */
	function autoCreate()
	{
		return true;
	}

	/**
	 * Check to see if external accounts can be created.
	 * Return true if external accounts can be created.
	 *
	 * NOTE: We are not allowed to add users to Discuz from the
	 * wiki so this always returns false.
	 *
	 * @return bool
	 * @access public
	 */
	function canCreateAccounts()
	{
		return false;
	}

	/**
	 * If you want to munge the case of an account name before the final
	 * check, now is your chance.
	 */
	function getCanonicalName( $username )
	{
		return $username;
	}

	/**
	 * When creating a user account, optionally fill in preferences and such.
	 * For instance, you might pull the email address or real name from the
	 * external user database.
	 *
	 * The User object is passed by reference so it can be modified; don't
	 * forget the & on your function declaration.
	 *
	 * NOTE: This gets the email address from SMF for the wiki account.
	 *
	 * @param User $user
	 * @access public
	 */
	function initUser(&$user)
	{
		//当新建用户的时候从discuz读取电邮等信息
		
		$username = htmlentities(strtolower($user->mName), ENT_QUOTES, 'UTF-8');
		$username = str_replace('&#039;', '\\\'', $username); // Allow apostrophes (Escape them though)

		//调试:看下用户名是否正确
                //echo "<script>alert('username(".$username.")init started!');</script>";

		if($data = uc_get_user(iconv("UTF-8", "UTF-8", $username))) { //Get information from UC
			list($uid, $username1, $email) = $data;
			$user->mEmail=$email; //Get email from UC
			$user->mid=$uid; //Get address from UC
		}

		$this->updateUser($user);
		$user->setToken();

		$user->setOption( 'enotifwatchlistpages', 1 );
		$user->setOption( 'enotifusertalkpages', 1 );
		$user->setOption( 'enotifminoredits', 1 );
		$user->setOption( 'enotifrevealaddr', 1 );

		$user->saveSettings(); 
	}

	/**
	 * Modify options in the login template.
	 *
	 * NOTE: Turned off some Template stuff here. Anyone who knows where
	 * to find all the template options please let me know. I was only able
	 * to find a few.
	 *
	 * @param UserLoginTemplate $template
	 * @access public
	 */
	function modifyUITemplate( &$template )
	{

		$template->set('usedomain',   false); // We do not want a domain name.
		$template->set('create',      false); // Remove option to create new accounts from the wiki.
		$template->set('useemail',    false); // Disable the mail new password box.

	}

	/**
	 * This prints an error when a MySQL error is found.
	 *
	 * @param string $message
	 * @access public
	 */
	function mySQLError( $message )
	{
		exit;
	}

	/**
	 * Set the domain this plugin is supposed to use when authenticating.
	 *
	 * NOTE: We do not use this.
	 *
	 * @param string $domain
	 * @access public
	 */
	function setDomain( $domain )
	{
		$this->domain = $domain;
	}

	/**
	 * Set the given password in the authentication database.
	 * Return true if successful.
	 *
	 * NOTE: We only allow the user to change their password via phpBB.
	 *
	 * @param string $password
	 * @return bool
	 * @access public
	 */
	function setPassword( $password )
	{
		return true;
	}

	/**
	 * Return true to prevent logins that don't authenticate here from being
	 * checked against the local database's password fields.
	 *
	 * This is just a question, and shouldn't perform any actions.
	 *
	 * Note: This forces a user to pass Authentication with the above
	 *       function authenticate(). So if a user changes their SMF
	 *       password, their old one will not work to log into the wiki.
	 *       Wiki does not have a way to update it's password when SMF
	 *       does. This however does not matter.
	 *
	 * @return bool
	 * @access public
	 */
	function strict()
	{
		return true;
	}

	/**
	 * Update user information in the external authentication database.
	 * Return true if successful.
	 *
	 * @param $user User object.
	 * @return bool
	 * @public
	 */
	function updateExternalDB( $user )
	{
		return true;
	}

	/**
	 * When a user logs in, optionally fill in preferences and such.
	 * For instance, you might pull the email address or real name from the
	 * external user database.
	 *
	 * The User object is passed by reference so it can be modified; don't
	 * forget the & on your function declaration.
	 *
	 * NOTE: Not useing right now.
	 *
	 * @param User $user
	 * @access public
	 */
	function updateUser( &$user )
	{
		return true;
	}

	/**
	 * Check whether there exists a user account with the given name.
	 * The name will be normalized to MediaWiki's requirements, so
	 * you might need to munge it (for instance, for lowercase initial
	 * letters).
	 *
	 * NOTE: MediaWiki checks its database for the username. If it has
	 *       no record of the username it then asks. "Is this really a
	 *       valid username?" If not then MediaWiki fails Authentication.
	 *
	 * @param string $username
	 * @return bool
	 * @access public
	 * @todo write this function.
	 */
	function userExists($username)
	{
		//用uc的接口查询用户是否存在
		$username = htmlentities(strtolower($username), ENT_QUOTES, 'UTF-8');
		$username = str_replace('&#039;', '\\\'', $username); // Allow apostrophes (Escape them though)

		//---------------------------------------------------------------------------------------------------
		if($data = uc_get_user(iconv("UTF-8", "UTF-8", $username))) {
			list($uid, $username1, $email) = $data;	
			return true;
		} else {
			return false;
		}

	}

	/**
	 * Check to see if the specific domain is a valid domain.
	 *
	 * @param string $domain
	 * @return bool
	 * @access public
	 */
	function validDomain( $domain )
	{
		return true;
	}

}

?>
