<!doctype html>

<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Name your access token</title>
</head>

<div>
    <h1>Name your access token</h1>
    By naming your access token you authorize <em>${client}</em> to use it.
    Make sure the nickname for your access token is unique!
</div>

<form action="${form_action}" method="get">
    <input type="hidden" name="sid" value="${sid}">

    <label for="nickname">Nickname</label>
    <input type="text" id="nickname" name="access_token_nickname" autofocus
           required>

    <input type="submit" value="Authorize">
</form>