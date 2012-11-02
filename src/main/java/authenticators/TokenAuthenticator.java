package authenticators;

import java.util.Arrays;

import tokens.TicketToken;
import tokens.Token;

public class TokenAuthenticator implements Authenticator {
  
  @Override
  public boolean authenticate(Token token) {
    if (token instanceof TicketToken) {
      TicketToken tt = (TicketToken) token;
      return Arrays.equals("userpass".getBytes(), tt.getTicket());
    }
    return false;
  }
  
  @Override
  public boolean validateUser(String user, Token token) {
    if (token instanceof TicketToken) {
      TicketToken tt = (TicketToken) token;
      // The reality here is it reaches out to the appropriate server and validates
      return new String(tt.getTicket()).startsWith(user);
    }
    return false;
  }
  
  @Override
  public String tokenClass() {
    return TicketToken.class.toString();
  }
  
  public TicketToken getToken(byte[] ticket) {
    return new TicketToken(ticket);
  }
}
