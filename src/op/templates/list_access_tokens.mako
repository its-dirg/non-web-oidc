<!DOCTYPE html>
<html>
<head lang="en">
    <meta charset="UTF-8">
    <title></title>
</head>
<body>
<ul>
    % for nick in access_tokens:
        <li>${nick}:
            <a href="/revoke_token?access_token=${access_tokens[nick] | u}">Revoke</a>
            <pre>${access_tokens[nick]}</pre>
        </li>
    % endfor

</ul>
</body>
</html>