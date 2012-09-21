<?php

if (class_exists('OC')) {
    // bootstrap already occurred? This shouldn't happen, but bail if it does.
    header('Location: /');
    exit;
}

// OC bootstrap.
set_include_path(dirname(dirname(__DIR__)) . PATH_SEPARATOR . get_include_path());
$RUNTIME_NOAPPS = TRUE; //no apps, yet
require_once 'lib/base.php';

// autoload classes in ../lib
spl_autoload_register(function ($class) {
    $file = dirname(__DIR__) . '/lib/' . strtr($class, '_\\', '//') . '.php';
    is_readable($file) && (require $file);
});


if (OC_User::isLoggedIn()) {
    OC_Util::redirectToDefaultPage();
}

// obj to sniff properties from Shibboleth
$shibEnv = new Coe_Shibboleth_Environment();

// Allows this directly to use lazy sessions, if needed
$shibGatekeeper = new Coe_Shibboleth_Gatekeeper($shibEnv);
$shibGatekeeper->protect(true);

$uid = $shibEnv->getUsername();

// verify the user is in an autogroup. Sadly Shibboleth doesn't provide these
// so we must check group affiliation via LDAP
$groupCn = 'CN=_PROVOST-COLLEGE-EDUCATION-USERS_autoGS,OU=AutoGroups,OU=Groups,OU=UF,DC=ad,DC=ufl,DC=edu';
$ldapConfig = (require dirname(__DIR__) . '/ldap-credentials.php');
$ldap = Coe_Ldap_Ufad::factory($ldapConfig);

$userAttrs = $ldap->getAttributesByGlid($uid);
if (!$userAttrs) {
    // @todo real error message
    header('Location: /ldap-user-not-found');
    exit;
}
if (!$ldap->isMemberOf($groupCn, $userAttrs)) {
    // @todo real error message
    header('Location: /not-in-AD-group');
    exit;
}

// dummy password
$max = mt_getrandmax();
$password = sha1(microtime(true) . mt_rand(0, $max) . mt_rand(0, $max) . mt_rand(0, $max));

// @todo is this necessary?
//OC_App::loadApps();

if (!OC_User::userExists($uid)) {
    OC_User::createUser($uid, $password);
}

$enabled = OC_User::isEnabled($uid);
if (!empty($uid) && $enabled) {
    session_regenerate_id(true);
    OC_User::setUserId($uid);
    OC_Hook::emit( "OC_User", "post_login", array( "uid" => $uid, 'password' => $password ));
}

header('Location: /');
