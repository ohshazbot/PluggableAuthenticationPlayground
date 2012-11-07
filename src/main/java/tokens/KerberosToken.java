package tokens;

public class KerberosToken implements AuthenticationToken {
  byte[] ticket;
  public KerberosToken(byte[] outToken) {
    ticket = outToken;
  }

  /**
   * 
   */
  private static final long serialVersionUID = 2580072029723054761L;
  
}
