create or replace function gentoken (username IN varchar2) return varchar2 as
language java name 'de.ichag.JWTToken.genToken(java.lang.String) return java.lang.String';

create or replace function checktoken (token IN varchar2) return varchar2 as
language java name 'de.ichag.JWTToken.checkToken(java.lang.String) return java.lang.String';

call dbms_java.grant_permission( 'ODI_DEMO', 'SYS:java.lang.RuntimePermission', 'accessDeclaredMembers', '' );



-- here's a sample JWT verifier in PL/SQL, but it wont work correctly because auf BASE64 encoding instead of BASE64URL encoding.

DECLARE
  token_vc varchar2(32767) := 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwOi8vTVBGRUlGRVItWU9HQTM3Iiwic3ViIjoiZGVtbyIsImlzcyI6Ik1QRkVJRkVSLVlPR0EzNyIsImV4cCI6MTYzMjQwMDA2NywiaWF0IjoxNjMyMzk2NDY3fQ.G6jYudOKKBpyAFPotrcfsO-PSfyoeEk9CsM7MkfUMnY';
  header_vc varchar2(32767);
  payload_vc varchar2(32767);
  signature_vc varchar2(32767);
  l_idx pls_integer;
  tmpraw raw(32767);
  mysignature_raw raw(32767);
  mysignature_vc varchar2(32767);
  user_vc varchar2(32767);
BEGIN
  l_idx := instr(token_vc,'.');
  header_vc := substr(token_vc,1,l_idx-1);
  token_vc := substr (token_vc, l_idx+1);

  l_idx := instr(token_vc,'.');
  payload_vc := substr(token_vc,1,l_idx-1);
  signature_vc := substr (token_vc, l_idx+1);
  mysignature_vc := header_vc||'.'||payload_vc;  
  
  dbms_output.put_line ('header: '||header_vc);
  dbms_output.put_line ('payload: '||payload_vc);
  dbms_output.put_line ('signature: '||signature_vc);
  
  tmpraw := utl_raw.cast_to_raw(header_vc);
  tmpraw := utl_encode.base64_decode(tmpraw);
  header_vc := utl_raw.cast_to_varchar2(tmpraw);
  
  tmpraw := utl_raw.cast_to_raw(payload_vc);
  tmpraw := utl_encode.base64_decode(tmpraw);
  payload_vc := utl_raw.cast_to_varchar2(tmpraw);

  dbms_output.put_line ('header: '||header_vc);
  dbms_output.put_line ('payload: '||payload_vc);
  
  user_vc := json_value(payload_vc, '$.sub');
  dbms_output.put_line ('user: '||user_vc);

  tmpraw := utl_raw.cast_to_raw(mysignature_vc);
  tmpraw := DBMS_CRYPTO.MAC(src => tmpraw, typ => DBMS_CRYPTO.HMAC_SH256, key => (utl_raw.cast_to_raw(json_value(payload_vc, '$.iss'))));
  dbms_output.put_line ('calculated decoded raw signature : '||tmpraw);
  
  --tmpraw := utl_encode.base64_encode(tmpraw);
  --dbms_output.put_line ('calculated encoded raw signature : '||tmpraw);
  --mysignature_vc := utl_raw.cast_to_varchar2(tmpraw);
  --dbms_output.put_line ('calculated encoded varchar signature : '||mysignature_vc);
  
  --dbms_output.put_line ('received encoded varchar signature : '||signature_vc);
  mysignature_raw := utl_raw.cast_to_raw(signature_vc);
  --dbms_output.put_line ('received encoded raw signature : '||mysignature_raw);
  mysignature_raw := utl_encode.base64_decode(mysignature_raw);
  dbms_output.put_line ('received decoded raw signature : '||mysignature_raw);


  if (tmpraw = mysignature_raw) then
     dbms_output.put_line ('signatures are identical, signature verified');
  end if;
END;

