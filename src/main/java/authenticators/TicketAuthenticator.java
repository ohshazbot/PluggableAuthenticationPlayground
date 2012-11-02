package authenticators;

import java.util.Arrays;

import thrift.PlugException;
import tokens.TicketToken;
import tokens.AuthenticationToken;

public class TicketAuthenticator implements Authenticator {
  
  @Override
  public boolean authenticate(AuthenticationToken token) {
    if (token instanceof TicketToken) {
      TicketToken tt = (TicketToken) token;
      return Arrays.equals("ticketuser_pass".getBytes(), tt.getTicket());
    }
    return false;
  }
  
  @Override
  public String tokenClass() {
    return TicketToken.class.toString();
  }
  
  public static TicketToken getToken(byte[] ticket) {
    return new TicketToken(ticket);
  }
  
  @Override
  public String getUser(AuthenticationToken token) throws PlugException {
    if (token instanceof TicketToken) {
      TicketToken tt = (TicketToken) token;
      // The reality here is it reaches out to the appropriate server and validates
      return new String(tt.getTicket()).split("_")[0];
    }
    throw new PlugException("Bad token, expected TicketToken");
  }
}
