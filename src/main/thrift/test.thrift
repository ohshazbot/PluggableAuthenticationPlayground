namespace java thrift

exception PlugException
{
  1:string msg
}

service PluggableSecurityTest
{
  bool ping();
  bool authenticate(1:binary token) throws (1:PlugException plugException)
  bool nonauthenticateoperation(1:string user, 2:binary token, 3:string operationRelatedData) throws (1:PlugException pe)
  string authenticationClass()
}