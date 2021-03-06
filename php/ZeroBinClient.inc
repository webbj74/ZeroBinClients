<?php
include 'ZeroBinSJCL.inc';

class ZeroBinClient
{
  private $paste_url = NULL;

  /**
   * Initializes ZeroBinClient
   *
   * Examples:
   * $encrypter = new ZeroBinClient(array('paste_url' => 'http://zerobin.local:8082/'));
   * $decrypter = new ZeroBinClient(array('paste_url' => 'http://zerobin.local:8082/?64c376879a41461d#BbGvGM7bFvNv2OqDndnDj42faDL3nx78Q7deadbeefA='));
   * $message = ZeroBinClient::decompress(ZeroBinClient::compress($message));
   */
  public function __construct($config) {
    if (!empty($config['paste_url'])) {
      $this->paste_url = parse_url($config['paste_url']);
      $this->paste_url['url'] = $config['paste_url'];
    }
    if ($this->pasteID() && $this->pageKey()) {
      if ($messages = $this->get()) {
        $this->displayMessages($this->pageKey(), $messages);
      }
    }
  }

  /**
   *  Converts a duration (in seconds) into human readable format.
   *
   *  @param int seconds
   *  @return string
   */
  public static function secondsToHuman($seconds) {
    if ($seconds<60) { 
      $v=floor($seconds); 
      return $v . ' second' . (($v>1)?'s':''); 
    }
    if ($seconds<60*60) { 
      $v=floor($seconds/60); 
      return $v . ' minute' . (($v>1)?'s':''); 
    }
    if ($seconds<60*60*24) { 
      $v=floor($seconds/(60*60)); 
      return $v . ' hour' . (($v>1)?'s':''); 
    }
    // If less than 2 months, display in days:
    if ($seconds<60*60*24*60) { 
      $v=floor($seconds/(60*60*24)); 
      return $v . ' day' . (($v>1)?'s':'');
    }
    $v=floor($seconds/(60*60*24*30)); 
    return $v . ' month' . (($v>1)?'s':'');
  }
  
  /**
   * Compress a message (deflate compression). Returns base64 encoded data.
   *
   * @param string message
   * @return base64 string data
   */
  public static function compress($message) {
    $utob = mb_convert_encoding($message, 'UTF-8', 'auto');
    $deflate = gzdeflate($utob);
    $preenc = mb_convert_encoding($deflate,'UTF-8', '8bit');
    return base64_encode($preenc);
  }

  /**
   * Decompress a message compressed with compress().
   * 
   * @param base64 string data
   * @return string message
   */
  public static function decompress($data) {
    $decode = base64_decode($data);
    $post_decode = mb_convert_encoding($decode, '8bit', 'UTF-8');
    $inflate = gzinflate($post_decode);
    return mb_convert_encoding($inflate, 'auto', 'UTF-8');
  }

  /**
   * Compress, then encrypt message with key.
   *
   * @param string key
   * @param string message
   * @return encrypted string data
   */
  public static function zeroCipher($key, $message) {
    return ZeroBinSJCL::encrypt($key,self::compress($message));
  }

  /**
   *  Decrypt message with key, then decompress.
   *
   *  @param key
   *  @param encrypted string data
   *  @return string readable message
   */
  public static function zeroDecipher($key, $data) {
    return self::decompress(ZeroBinSJCL::decrypt($key, $data));
  }

  /**
   * @return the current script location (without search or hash part of the URL).
   *   eg. http://server.com/zero/?aaaa#bbbb --> http://server.com/zero/
   */
  public function scriptLocation() {
    return preg_replace('/\?.*$/', '', $this->paste_url['url']);
  }

  /**
   * @return the paste unique identifier from the URL
   *   eg. 'c05354954c49a487'
   */
  public function pasteID() {
    return (!empty($this->paste_url['query'])) ? $this->paste_url['query'] : NULL;
  }

  /**
   * Return the deciphering key stored in anchor part of the URL
   */
  function pageKey() {
    return (!empty($this->paste_url['fragment'])) ? preg_replace('/=.*$/', '=', $this->paste_url['fragment']) : NULL;
  }
  

  /**
   * Return the decrypted text, including discussion (if open)
   *
   * @param string key : decryption key
   * @param array comments : Array of messages to display (items = array with keys ('data','meta')
   */
  function displayMessages($key, $comments) {
    try { 
      // Try to decrypt the paste.
      $cleartext = $this->zeroDecipher($key, $comments[0]->data);
    }
    catch (Exception $err) {
      error_log('Error: Could not decrypt data: ' . $err->getMessage());
      return;
    }
    $result = array();
    $result['cleartext'] = array(
      'data' => $cleartext,
      'language' => $comments[0]['meta']['language'],
     );

    // Display paste expiration.
    if (!empty($comments[0]['meta']['expire_date'])) {
      $result['cleartext']['remainingtime'] = 'This document will expire in ' . secondsToHuman($comments[0]['meta']['remaining_time']) . '.';
    }
    if (!empty($comments[0]['meta']['burnafterreading'])) {
      $result['cleartext']['remainingtime'] = 'FOR YOUR EYES ONLY. Don\'t close this window, this message will self destruct.';
    }
/**
 * TODO: Convert Discussion Processing Code to PHP
 *
    // If the discussion is opened on this paste, display it.
    if (comments[0].meta.opendiscussion) {
      $('div#comments').html('');
      // For each comment.
      for (var i = 1; i < comments.length; i++) {
        var comment=comments[i];
        var cleartext="[Could not decrypt comment ; Wrong key ?]";
        try {
          cleartext = zeroDecipher(key, comment.data);
        } catch(err) { }
        var place = $('div#comments');
        // If parent comment exists, display below (CSS will automatically shift it right.)
        var cname = 'div#comment_'+comment.meta.parentid
  
        // If the element exists in page
        if ($(cname).length) {
          place = $(cname);
        }
        var divComment = $('<div class="row"><div class="span12"><div class="comment" id="comment_' + comment.meta.commentid+'">'
                           + '<div class="commentmeta"><strong class="nickname"></strong><span class="commentdate muted"></span></div><div class="commentdata"></div>'
                           + '</div></div></div>');
        setElementText(divComment.find('div.commentdata'), cleartext);
        // Convert URLs to clickable links in comment.
        urls2links(divComment.find('div.commentdata'));
        divComment.find('strong.nickname').html('<i>(Anonymous)</i>');
  
        // Try to get optional nickname:
        try {
          divComment.find('strong.nickname').text(zeroDecipher(key, comment.meta.nickname));
        } catch(err) { }
        divComment.find('span.commentdate').text(' - '+(new Date(comment.meta.postdate*1000).toUTCString())+' ').attr('title','CommentID: ' + comment.meta.commentid);
  
        // If an avatar is available, display it.
        if (comment.meta.vizhash) {
          divComment.find('strong.nickname').before('<img src="' + comment.meta.vizhash + '" class="vizhash" title="Anonymous avatar (Vizhash of the IP address)" />');
        }
  
        place.append(divComment);
      }
      $('div#comments').append('<div class="comment"><div class="row"><div class="span12"><button class="btn" onclick="open_reply($(this),\'' + pasteID() + '\');return false;">Add comment</button></div></div></div>');
      $('div#discussion').show();
    }
 *
 * END of Discussion Processing Code
 */
    return $result;
  }

  /**
   * Send a reply in a discussion.
   * @param string parentid : the comment identifier we want to send a reply to.
   */
  function send_comment($parentid, $replymessage) {
    // Do not send if no data.
    if (empty($replymessage)) {
        return;
    }
    throw new Exception("ZeroBinClient::send_comment has not been implemented.");
/**
 * TODO: Convert Comment Adding Code to PHP
 *
    showStatus('Sending comment...', spin=true);
    var cipherdata = zeroCipher(pageKey(), $('textarea#replymessage').val());
    var ciphernickname = '';
    var nick=$('input#nickname').val();
    if (nick != '') {
        ciphernickname = zeroCipher(pageKey(), nick);
    }
    var data_to_send = { data:cipherdata,
                         parentid: parentid,
                         pasteid:  pasteID(),
                         nickname: ciphernickname
                       };

    $.post(scriptLocation(), data_to_send, 'json')
        .error(function() {
            showError('Error: Comment could not be sent.');
        })
        .success(function(data) {
            if (data.status == 0) {
                showStatus('Comment posted.');
                location.reload();
            }
            else if (data.status==1) {
                showError('Error: Could not post comment: '+data.message);
            }
            else {
                showError('Error: Could not post comment.');
            }
        });
 *
 * END of Comment Adding Code
 */
  }

  /**
   * Retrieves SJCL-encrypted data from a JSON object embedded in the provided ZeroBin URL
   */ 
  function get() {
    $ch = curl_init($this->paste_url['url']);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION ,1);
    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $response = curl_exec($ch);
    $return_value = NULL;
    $response_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    if ($response_code == 200) {
      if (preg_match('#<div id="cipherdata" style="display:none;">(.*)</div>#', $response, $matches)) {
        $return_value = json_decode(html_entity_decode($matches[1]));
      }
    }
    else {
      throw new Exception("ZeroBinClient::post received HTTP Error Code {$response_code}");
    }
    return $return_value;
  }

  /**
   * Posts a JSON object with SJCL-compatible encrypted data to ZeroBin
   */ 
  function post($data) {
    $form_parts = array();
    foreach ($data as $key => $value) {
      $form_parts[]= urlencode($key) . '=' . urlencode($value);
    }
    $postfields = implode('&',$form_parts);
    
    $ch = curl_init($this->scriptLocation());
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $postfields);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION ,1);
    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $response = curl_exec($ch);
    
    $return_value = NULL;
    $response_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    if ($response_code == 200) {
      $return_value = json_decode($response);
    }
    else {
      throw new Exception("ZeroBinClient::post received HTTP Error Code {$response_code}");
    }
    return $return_value;
  }
  
  /**
   *  Send a new paste to server
   */
  function send_data($messageValue, $pasteExpiration = '3days', $language = 'sh', $opendiscussion = 0) {
    // Do not send if no data.
    if (empty($messageValue)) {
      return;
    }

    $randomkey = $this->randomBase64Str(44);

    $cipherdata = ''; $this->zeroCipher($randomkey, $messageValue);

    $data_to_send = array(
      'data' => $cipherdata,
      'expire' => $pasteExpiration,
      'language' => $language,
      'opendiscussion' => $opendiscussion,
    );
    
    try {
      if ($data = $this->post($data_to_send)) {
        if ($data->status == 0) {
          echo $this->scriptLocation() . "?" . $data->id . '#' . $randomkey;
        }
        else {
          error_log('Error: Could not create paste - ' . $data->message);
        }
      }
      else {
        error_log('Error: Could not create paste.');
      }
    }
    catch (Exception $err) {
      error_log('Error: Data could not be sent.' . $err->getMessage());
      return;
    }
  }
}

$unimplemented_javascript =<<<TO_ADD_TO_ZEROBINCLIENT

$(function() {
    $('select#pasteExpiration').change(function() {
        if ($(this).val() == 'burn') {
            $('div#opendisc').addClass('buttondisabled');
            $('input#opendiscussion').attr('disabled',true);
        }
        else {
            $('div#opendisc').removeClass('buttondisabled');
            $('input#opendiscussion').removeAttr('disabled');
        }
    });


    // Display an existing paste
    if ($('div#cipherdata').text().length > 1) {
        // Missing decryption key in URL ?
        if (window.location.hash.length == 0) {
            showError('Error: Cannot decrypt paste - Decryption key missing in URL.');
            return;
        }

        // List of messages to display
        var messages = jQuery.parseJSON($('div#cipherdata').text());

        // Show proper elements on screen.
        stateExistingPaste();

        displayMessages(pageKey(), messages);
    }
    // Display error message from php code.
    else if ($('div#errormessage').text().length>1) {
        showError('Error: ' + $('div#errormessage').text());
    }
    // Create a new paste.
    else {
        newPaste();
    }
});
TO_ADD_TO_ZEROBINCLIENT;

