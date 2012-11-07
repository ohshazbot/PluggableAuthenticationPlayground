package authenticators;

import java.security.PrivilegedAction;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import thrift.PlugException;
import tokens.AuthenticationToken;
import tokens.KerberosToken;

public class KerberosAuthenticator implements Authenticator {
  
  @Override
  public boolean authenticate(AuthenticationToken token) {
    // TODO Auto-generated method stub
    return false;
  }
  
  @Override
  public String tokenClass() {
    // TODO Auto-generated method stub
    return null;
  }
  
  @Override
  public String getUser(AuthenticationToken token) throws PlugException {
    // TODO Auto-generated method stub
    return null;
  }
  
  public static KerberosToken getToken(String user, char[] pass) throws LoginException, GSSException {
    System.setProperty( "sun.security.krb5.debug", "true");
    System.setProperty( "java.security.krb5.realm", "SQRRL.COM"); 
    System.setProperty( "java.security.krb5.kdc", "192.168.10.146");
    System.setProperty( "java.security.auth.login.config", "./conf/jaas.conf");
    System.setProperty( "javax.security.auth.useSubjectCredsOnly", "true");

    Oid oid = new Oid("1.2.840.113554.1.2.2");
    LoginContext loginCtx = null;
    // "Client" references the JAAS configuration in the jaas.conf file.
    loginCtx = new LoginContext("Client", new LoginCallbackHandler(user, pass));
    loginCtx.login();
    Subject subject = loginCtx.getSubject();
    
    GSSManager manager = GSSManager.getInstance();
    GSSName serverName = manager.createName( "accumulo", GSSName.NT_HOSTBASED_SERVICE);
    final GSSContext context = manager.createContext( serverName, oid, null, GSSContext.DEFAULT_LIFETIME);
    // The GSS context initiation has to be performed as a privileged action.
    byte[] serviceTicket = Subject.doAs( subject, new PrivilegedAction<byte[]>() {
      public byte[] run() {
        try {
          byte[] token = new byte[0];
          // This is a one pass context initialisation.
          context.requestMutualAuth( false);
          context.requestCredDeleg( false);
          return context.initSecContext( token, 0, token.length);
        }
        catch ( GSSException e) {
          e.printStackTrace();
          return null;
        }
      }
    } );
    
    return new KerberosToken(serviceTicket);
    
  }
}
