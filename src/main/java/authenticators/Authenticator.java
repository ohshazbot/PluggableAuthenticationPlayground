package authenticators;

import tokens.Token;

public interface Authenticator {
  public boolean authenticate(Token token);
  
  public boolean validateUser(String user, Token token);
  
  public String tokenClass();
  
  //Highly advise having an Authenticator.createToken(args)
}
