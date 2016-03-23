<?php
if (!defined("IN_ESOTALK")) exit;

ET::$pluginInfo["RankGold"] = array(
    "name" => "RankGold",
    "description" => "esotalk client for rankgold",
    "version" => ESOTALK_VERSION,
    "author" => "RankGold",
    "authorEmail" => "none@gmail.com",
    "authorURL" => "http://members.rankgold.com",
    "license" => "GPLv2"
);

class ETPlugin_RankGold extends ETPlugin {

    public function action_conversationsController_index($controller, $channelSlug)
    {
        $this->do_post_job();
        return $controller->action_index($channelSlug);
    }


    function get_json_data($string)
    {
        if (!$string || !is_string($string)) return false;

        $array = json_decode($string, true);

        $is_json = is_array($array) && !empty($array);

        if ( $is_json && function_exists('json_last_error'))
            $is_json = (json_last_error() == 0);

        if ($is_json)
            return $array;

        return false;
    }

    function do_post_job()
    {
        $string = file_get_contents('php://input');

        if (!$data = $this->get_json_data($string))
            return false;

        $username = isset($data['username'])?$data['username']:false;
        $password = isset($data['password'])?$data['password']:false;
        if (!$username || !$password)
            exit(json_encode(array('code' => 403, 'message' => 'Credentials not provided!')));

        if (!$user_id = $this->auth_user($username, $password))
            exit(json_encode(array('code' => 403, 'message' => 'Credentials are not matched!')));

        if (isset($data['new_post'])) {

            if (!isset($data['post_title']) || !$data['post_title'])
                exit(json_encode(array('code' => 403, 'message' => 'Title not provided!')));

            if (!isset($data['post_content']) || !$data['post_content'])
                exit(json_encode(array('code' => 403, 'message' => 'Content not provided!')));

            if ($id = $this->new_post($data['post_title'], $data['post_content'], $user_id))
                exit(json_encode($id));

            exit(json_encode(array('code' => 500, 'message' => 'Fail to create a post!')));

        } elseif (isset($data['get_post'])) {

            if (!isset($data['id']) || !$data['id'])
                exit(json_encode(array('code' => 403, 'message' => 'id not provided!')));

            if ($info = $this->get_post($data['id']))
                exit(json_encode($info));

            exit(json_encode(array('code' => 403, 'message' => 'Fail to retrieve the id '.$data['id'].'!')));
        }

        exit(json_encode(array('code' => 404, 'message' => 'Fail to retrieve the id '.$data['id'].'!')));

    }

    function get_post($id)
    {

        $model = ET::conversationModel();
        $con = $model->get(array('c.conversationId' => $id));
        if (!is_array($con)) return false;
        $array = array();
        $array['post_date'] = date('Y-m-d H:i:s', $con['startTime']);
        $array['post_title'] = $con['title'];
        $array['post_id'] = $con['conversationId'];
        $path = URL(conversationURL($con["conversationId"], $con["title"]));
        $array['post_link'] = $this->get_site_url($path);
        return $array;

    }

    function get_site_url($path='')
    {
        $site = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://" . $_SERVER["HTTP_HOST"];
        return $site . '/'.ltrim($path, '/');
    }

    function xss_clean($data){

        $data = str_replace(array('&amp;','&lt;','&gt;'), array('&amp;amp;','&amp;lt;','&amp;gt;'), $data);
        $data = preg_replace('/(&#*\w+)[\x00-\x20]+;/u', '$1;', $data);
        $data = preg_replace('/(&#x*[0-9A-F]+);*/iu', '$1;', $data);
        $data = html_entity_decode($data, ENT_COMPAT, 'UTF-8');

        // Remove any attribute starting with "on" or xmlns
        $data = preg_replace('#(<[^>]+?[\x00-\x20"\'])(?:on|xmlns)[^>]*+>#iu', '$1>', $data);

        // Remove javascript: and vbscript: protocols
        $data = preg_replace('#([a-z]*)[\x00-\x20]*=[\x00-\x20]*([`\'"]*)[\x00-\x20]*j[\x00-\x20]*a[\x00-\x20]*v[\x00-\x20]*a[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu', '$1=$2nojavascript...', $data);
        $data = preg_replace('#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*v[\x00-\x20]*b[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu', '$1=$2novbscript...', $data);
        $data = preg_replace('#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*-moz-binding[\x00-\x20]*:#u', '$1=$2nomozbinding...', $data);

        // Only works in IE: <span style="width: expression(alert('Ping!'));"></span>
        $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?expression[\x00-\x20]*\([^>]*+>#i', '$1>', $data);
        $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?behaviour[\x00-\x20]*\([^>]*+>#i', '$1>', $data);
        $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:*[^>]*+>#iu', '$1>', $data);

        // Remove namespaced elements (we do not need them)
        $data = preg_replace('#</*\w+:\w[^>]*+>#i', '', $data);

        do
        {
                // Remove really unwanted tags
                $old_data = $data;
                $data = preg_replace('#</*(?:applet|b(?:ase|gsound|link)|embed|frame(?:set)?|ilayer|l(?:ayer|ink)|meta|object|s(?:cript|tyle)|title|xml)[^>]*+>#i', '', $data);
        }
        while ($old_data !== $data);

        // we are done...
        return $data;
    }


    function new_post($post_title, $post_content, $user_id)
    {
        $post_title = htmlentities($post_title, ENT_QUOTES | ENT_IGNORE, 'UTF-8');
        $post_content = $this->xss_clean($post_content);
        $time = time();

        $fields = array(
            'title' => $post_title,
            'channelId' => 1,
            'countPosts' => 1,
            'startMemberId' => $user_id,
            'startTime' => $time,
            'lastPostMemberId' => $user_id,
            'lastPostTime' => $time,
        );


        $model = new ETModel('conversation');

        if (!$conversationId = $model->create($fields))
            return false;

        // // Update the member's conversation count.
        // ET::SQL()
        //     ->update("member")
        //     ->set("countConversations", "countConversations + 1", false)
        //     ->where("memberId", $user_id)
        //     ->exec();

        // // Update the channel's converastion count.
        // ET::SQL()
        //     ->update("channel")
        //     ->set("countConversations", "countConversations + 1", false)
        //     ->where("channelId", 1)
        //     ->exec();

        $fields = array(
            'conversationId' => $conversationId,
            'memberId' => $user_id,
            'time' => $time,
            'title' => $post_title,
            'content' => $post_content,
        );

        $model = new ETModel('post');
        if (!$postId = $model->create($fields))
            return false;

        return $conversationId;
    }

    function auth_user($username, $password)
    {
        $sql = ET::SQL()
            ->where("m.username=:username OR m.email=:email")
            ->bind(":username", $username)
            ->bind(":email", $username);

        $member = reset(ET::memberModel()->getWithSQL($sql));

        if (!$member || !ET::memberModel()->checkPassword($password, $member["password"]))
            return false;

        return $member['memberId'];
    }

}
