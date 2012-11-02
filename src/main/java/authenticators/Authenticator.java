package authenticators;

import thrift.PlugException;
import tokens.AuthenticationToken;

public interface Authenticator {
  public boolean authenticate(AuthenticationToken token);
    
  public String tokenClass();

  public String getUser(AuthenticationToken token) throws PlugException;
  
  //Highly advise having an Authenticator.createToken(args)
}
