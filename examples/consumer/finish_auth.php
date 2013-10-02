<?php

require_once "common.php";
// Includes required files
require_once "Auth/OpenID/Consumer.php";
require_once "Auth/OpenID/FileStore.php";
require_once "Auth/OpenID/AX.php";
session_start();

function escape($thing) {
    return htmlentities($thing);
}

function run() {
    $consumer = getConsumer();

    // Complete the authentication process using the server's
    // response.
    $return_to = getReturnTo();
    $response = $consumer->complete($return_to);

    // Check the response status.
    if ($response->status == Auth_OpenID_CANCEL) {
        // This means the authentication was cancelled.
        $msg = 'Verification cancelled.';
    } else if ($response->status == Auth_OpenID_FAILURE) {
        // Authentication failed; display the error message.
        $msg = "OpenID authentication failed: " . $response->message;
    } else if ($response->status == Auth_OpenID_SUCCESS) {
        // This means the authentication succeeded; extract the
        // identity URL and Simple Registration data (if it was
        // returned).
        $openid = $response->getDisplayIdentifier();
        $esc_identity = escape($openid);

        $success = sprintf('You have successfully verified ' .
                           '<a href="%s">%s</a> as your identity.',
                           $esc_identity, $esc_identity);

        if ($response->endpoint->canonicalID) {
            $escaped_canonicalID = escape($response->endpoint->canonicalID);
            $success .= '  (XRI CanonicalID: '.$escaped_canonicalID.') ';
        }

        
        // Get registration informations
    $ax = new Auth_OpenID_AX_FetchResponse();
    $obj = $ax->fromSuccessResponse($response);
	
        if (@$obj->data["http://axschema.org/contact/email"][0]) {
            $success .= "  You also returned '".escape($obj->data["http://axschema.org/contact/email"][0]).
                "' as your email.";
        }

        if (@$obj->data["http://axschema.org/namePerson/first"]) {
            $success .= "  Your first name is '".escape($obj->data["http://axschema.org/namePerson/first"][0]).
                "'.";
        }

        if (@$obj->data["http://axschema.org/namePerson/last"]) {
            $success .= "  Your last name is '".escape($obj->data["http://axschema.org/namePerson/last"][0]).
                "'.";
        }

	$pape_resp = Auth_OpenID_PAPE_Response::fromSuccessResponse($response);

	if ($pape_resp) {
            if ($pape_resp->auth_policies) {
                $success .= "<p>The following PAPE policies affected the authentication:</p><ul>";

                foreach ($pape_resp->auth_policies as $uri) {
                    $escaped_uri = escape($uri);
                    $success .= "<li><tt>$escaped_uri</tt></li>";
                }

                $success .= "</ul>";
            } else {
                $success .= "<p>No PAPE policies affected the authentication.</p>";
            }

            if ($pape_resp->auth_age) {
                $age = escape($pape_resp->auth_age);
                $success .= "<p>The authentication age returned by the " .
                    "server is: <tt>".$age."</tt></p>";
            }

            if ($pape_resp->nist_auth_level) {
                $auth_level = escape($pape_resp->nist_auth_level);
                $success .= "<p>The NIST auth level returned by the " .
                    "server is: <tt>".$auth_level."</tt></p>";
            }

	} else {
            $success .= "<p>No PAPE response was sent by the provider.</p>";
	}
    }

    include 'index.php';
}

run();

?>
