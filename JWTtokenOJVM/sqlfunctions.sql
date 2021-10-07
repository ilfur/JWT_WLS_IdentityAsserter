create or replace function gentoken (username IN varchar2) return varchar2 as
language java name 'de.ichag.JWTToken.genToken(java.lang.String) return java.lang.String';

create or replace function checktoken (token IN varchar2) return varchar2 as
language java name 'de.ichag.JWTToken.checkToken(java.lang.String) return java.lang.String';

call dbms_java.grant_permission( 'ODI_DEMO', 'SYS:java.lang.RuntimePermission', 'accessDeclaredMembers', '' );