package tokens;



public class UsernamePasswordToken implements Token {
  
  /**
   * 
   */
  private static final long serialVersionUID = -7228914324185016907L;
  
  private String user;
  private byte[] pass;
  
  public UsernamePasswordToken() {
    user = null;
    pass = null;
  }
  
  public UsernamePasswordToken(String username, byte[] password) {
    user = username;
    pass = password;
  }
  
  public String getUsername() {
    return user;
  }
  
  public byte[] getPassword() {
    return pass;
  }
  
  public String toString() {
    return user + " -> " + new String(pass);
  }
 }
