CodeIgniter-Twitter
=============

A complete library giving you twitter oauth authentication and api access.

Requirements
-------

1. PHP 5.1+
2. CodeIgniter 2.0

Usage
-------

### Basic Setup

1. Set your consumer key and consumer secret in application/config/tweet.php
2. See application/controllers/tweet_test.php for an example of how to use the library.

### API Requests

All calls can be made using a simple 'call' method.

Look through the [Twitter API Documentation](http://dev.twitter.com/doc/) to find the method you request to make.

The documentation will tell you if the request is a 'get' or 'post' request.
Then, simply use:

	// Example call structure:
	// 
	// $this->tweet->call($http_method, $request_uri, $params);

	$user = $this->tweet->call('get', 'users/show', array('screen_name' => 'elliothaughin'));

Parameters listed in the documentation are simply set using an associative array as the 3rd parameter for the call method;
Requests will usually return an object on success, or bool (false) for failures.

I will be working to add more exception handling so you have a better idea of what's working and what failed.

Todo
-------

1. Search and trends methods.
2. Better exception handling.

Official Page
-------

[Elliot Haughin: Code](http://www.haughin.com/code/)
