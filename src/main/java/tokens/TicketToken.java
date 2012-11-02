package tokens;

public class TicketToken implements Token {

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
}
