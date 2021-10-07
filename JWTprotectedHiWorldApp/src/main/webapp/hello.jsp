<%-- 
    Document   : hello.jsp
    Created on : Sep 22, 2021, 2:23:33 PM
    Author     : MPFEIFER
--%>

<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
  <head>
    <title>Browser Based Authentication Example Welcome Page</title>
  </head>
  <h1> Browser Based Authentication Example Welcome Page </h1>
  <p> Welcome <%= request.getRemoteUser() %>!
  </blockquote>
  </body>
</html>