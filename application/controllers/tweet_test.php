<?php

	class Tweet_test extends CI_Controller {
		
		function __construct()
		{
			parent::__construct();
			
			// It really is best to auto-load this library!
			$this->load->library('tweet');
			
			if ( !$this->tweet->logged_in() )
			{
				// This is where the url will go to after auth.
				// ( Callback url )
				
				$this->tweet->set_callback(site_url('tweet_test/auth'));
				
				// Send the user off for login!
				$this->tweet->login();
			}
		}
		
		function index()
		{
			echo 'hi there';
		}
		
		function auth()
		{
			if ( !$this->tweet->logged_in() )
			{
				die('some how you are not logged in');
			}
			
			$tokens = $this->tweet->get_tokens();
			
			
			// Enabling debug will show you any errors in the calls you're making, e.g:
			// 
			// $this->tweet->enable_debug(TRUE);
			// $user = $this->tweet->call('get', 'account/verify_credentiaals');
			// 
			// Will throw an error with a stacktrace.
			
			$user 			= $this->tweet->call('get', 'account/verify_credentiaals');
			$friendship 	= $this->tweet->call('get', 'friendships/show', array('source_screen_name' => $user->screen_name, 'target_screen_name' => 'elliothaughin'));
			
			if ( $friendship->relationship->target->following === FALSE )
			{
				$this->tweet->call('post', 'friendships/create', array('screen_name' => $user->screen_name, 'follow' => TRUE));
			}
			
			 $this->tweet->call('post', 'statuses/update', array('status' => 'Testing #CodeIgniter Twitter library by @elliothaughin - http://bit.ly/grHmua'));
			
			$options = array(
						'count' => 10,
						'page' 	=> 2,
						'include_entities' => 1
			);
			
			$timeline = $this->tweet->call('get', 'statuses/home_timeline');
			
			var_dump($timeline);
		}
	}