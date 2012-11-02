package authenticators;

import java.util.Arrays;

import thrift.PlugException;
import tokens.AuthenticationToken;
import tokens.UsernamePasswordToken;

public class UserPassAuthenticator implements Authenticator {
  
  @Override
  public boolean authenticate(AuthenticationToken token) {
    if (token instanceof UsernamePasswordToken) {
      UsernamePasswordToken upt = (UsernamePasswordToken) token;
      return upt.getUsername().equals("upuser") && Arrays.equals("pass".getBytes(), upt.getPassword());
    }
    return false;
  }
  
  @Override
  public String tokenClass() {
    return UsernamePasswordToken.class.getName();
  }
  
  public static UsernamePasswordToken getToken(String user, byte[] pass) {
    return new UsernamePasswordToken(user, pass);
  }

  @Override
  public String getUser(AuthenticationToken token) throws PlugException {
    if (token instanceof UsernamePasswordToken)
      return ((UsernamePasswordToken) token).getUsername();
    throw new PlugException("Bad token, expected UsernamePasswordToken");
  }
  
}
