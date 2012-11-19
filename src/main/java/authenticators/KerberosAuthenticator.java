package authenticators;

import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;

import thrift.PlugException;
import tokens.AuthenticationToken;
import tokens.KerberosToken;

public class KerberosAuthenticator {// implements Authenticator {
  Subject subject;
  
  public KerberosAuthenticator() throws GSSException, LoginException {
    System.setProperty("sun.security.krb5.debug", "false");
    System.setProperty("java.security.krb5.realm", "SQRRL.COM");
    System.setProperty("java.security.krb5.kdc", "172.16.101.34");
    System.setProperty("java.security.auth.login.config", "./conf/jaas.conf");
    System.setProperty("javax.security.auth.useSubjectCredsOnly", "true");
    
    // "Client" references the JAAS configuration in the jaas.conf file.
    LoginContext loginCtx = null;
    loginCtx = new LoginContext("Server", new LoginCallbackHandler("secret".toCharArray()));
    loginCtx.login();
    subject = loginCtx.getSubject();
  }
  
  // @Override
  public boolean authenticate(final AuthenticationToken token) {
    final KerberosToken kt = (KerberosToken) token;
    return kt.getUser().equals(Subject.doAs(subject, new PrivilegedAction<String>() {
      public String run() {
        // This is a one pass context initialization.
        KerberosTicketDecoder decode = new KerberosTicketDecoder(kt.session, subject);
        return decode.getClientPrincipalName();
      }
    }));
  }
  
  // @Override
  public String tokenClass() {
    // TODO Auto-generated method stub
    return null;
  }
  
  // @Override
  public String getUser(AuthenticationToken token) throws PlugException, GSSException {
    final KerberosToken kt = (KerberosToken) token;
    
    authenticate(token);
    return kt.getUser();
  }
  
  public static KerberosToken getToken(String user, char[] pass) throws LoginException, GSSException {
    System.setProperty("sun.security.krb5.debug", "false");
    System.setProperty("java.security.krb5.realm", "SQRRL.COM");
    System.setProperty("java.security.krb5.kdc", "172.16.101.34");
    System.setProperty("java.security.auth.login.config", "./conf/jaas.conf");
    System.setProperty("javax.security.auth.useSubjectCredsOnly", "true");
    Oid oid = new Oid("1.2.840.113554.1.2.2");
    
    LoginContext loginCtx = null;
    // "Client" references the JAAS configuration in the jaas.conf file.
    loginCtx = new LoginContext("Client", new LoginCallbackHandler(user, pass));
    loginCtx.login();
    final Subject subject = loginCtx.getSubject();
    
    GSSManager manager = GSSManager.getInstance();
    GSSName serverName = manager.createName("accumulo", GSSName.NT_USER_NAME);
    final GSSContext context = manager.createContext(serverName, oid, null, 3);
    // The GSS context initiation has to be performed as a privileged action.
    byte[] serviceTicket = Subject.doAs(subject, new PrivilegedAction<byte[]>() {
      public byte[] run() {
        try {
          byte[] token = new byte[0];
          // This is a one pass context initialization.
          context.requestMutualAuth(false);
          context.requestCredDeleg(false);
          return context.initSecContext(token, 0, 0);
          
        } catch (GSSException e) {
          e.printStackTrace();
          return null;
        }
      }
    });
    
    return new KerberosToken(serviceTicket, context, user);
  }  
}
