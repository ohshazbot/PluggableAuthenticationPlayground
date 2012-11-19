package tokens;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.management.ManagementFactory;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.MessageProp;

public class KerberosToken implements AuthenticationToken {
  public byte[] session;
  transient GSSContext context;
  public String user;
  
  public KerberosToken(byte[] outToken, GSSContext context, String user) {
    session = outToken;
    this.context = context;
    this.user = user;
  }
  
  /**
   * 
   */
  private static final long serialVersionUID = 2580072029723054761L;
  
  private void readObject(ObjectInputStream aInputStream) throws IOException, ClassNotFoundException {
    aInputStream.defaultReadObject();
  }
  
  private void writeObject(ObjectOutputStream aOutputStream) throws IOException {
    aOutputStream.defaultWriteObject();
  }
  
  public void destroy() {
    if (context != null)
      try {
        context.dispose();
      } catch (GSSException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
      }
    for (int i = 0; i < session.length; i++)
      session[i] = 0x00;
    session = null;
  }
  
  @Override
  public boolean isDestroyed() {
    return context == null;
  }

  public String getUser() {
    return user;
  }
  
}
