package authenticators;

import java.util.Arrays;

import tokens.Token;
import tokens.UsernamePasswordToken;

public class UserPassAuthenticator implements Authenticator {
  
  @Override
  public boolean authenticate(Token token) {
    if (token instanceof UsernamePasswordToken) {
      UsernamePasswordToken upt = (UsernamePasswordToken) token;
      return upt.getUsername().equals("user") && Arrays.equals("pass".getBytes(), upt.getPassword());
    }
    return false;
  }
  
  @Override
  public boolean validateUser(String user, Token token) {
    if (token instanceof UsernamePasswordToken)
      return user.equals(((UsernamePasswordToken) token).getUsername());
    return false;
  }
  
  @Override
  public String tokenClass() {
    return UsernamePasswordToken.class.getName();
  }
  
  public static UsernamePasswordToken getToken(String user, byte[] pass) {
    return new UsernamePasswordToken(user, pass);
  }
  
}
