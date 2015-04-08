<!doctype html>

<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Please login</title>

    <style type="text/css">
        .container {
            width: 100px;
            clear: both;
        }

        .container input {
            width: 100%;
            clear: right;
        }

    </style>
</head>

<body>
<div>
    <h1>${title}</h1>
</div>

<div class="container">
    <form action="${action}" method="post" class="login form">
        <input type="hidden" name="query" value="${query}"/>
        <input type="hidden" name="acr_values" value="${acr}"/>

        <p>
            <label for="login">${login_title}</label>
            <input type="text" id="login" name="login" value="${login}"
                   autofocus>
        </p>

        <p>
            <label for="password">${passwd_title}</label>
            <input type="password" id="password" name="password"
                   value="${password}">
        </p>

        <input type="submit" value="${submit_text}">
    </form>
</div>

