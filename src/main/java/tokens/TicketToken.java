package tokens;

public class TicketToken implements AuthenticationToken {

  /**
   * 
   */
  private static final long serialVersionUID = 7253702007213309248L;
  
  private byte[] ticket;
  public TicketToken(){};
  public TicketToken(byte[] ticket) {
    this.ticket = ticket;
  }
  
  public byte[] getTicket() {
    return ticket;
  }
  
  public void setTicket(byte[] ticket){
    this.ticket = ticket;
  }
  
  public void destroy() {
    for (int i = 0; i < ticket.length; i++)
      ticket[i] = 0x00;
    ticket = null;
  }
  @Override
  public boolean isDestroyed() {
    return ticket==null;
  }
}
