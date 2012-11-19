package authenticators;

import java.util.Iterator;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosTicket;

import sun.security.krb5.EncryptionKey;
import sun.security.krb5.internal.EncTicketPart;
import sun.security.krb5.internal.Ticket;
import sun.security.krb5.internal.crypto.KeyUsage;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

class KerberosTicketDecoder {
  
  private byte[] serviceTicket;
  private Subject subject;
  private boolean decoded = false;
  private EncryptionKey sessionKey;
  private String cname;
  
  /**
   * Construct a Kerberos Ticket Decoder. This takes the service ticket that is to be decoded and the JAAS subject that contains the secret key for the target
   * service.
   * 
   * @param serviceTicket
   *          the AP-REQ service ticket that is to be decode
   * @param subject
   *          the JAAS subject containing the secret key for the server principal
   */
  public KerberosTicketDecoder(byte[] serviceTicket, Subject subject) {
    this.serviceTicket = serviceTicket;
    this.subject = subject;
  }
  
  /**
   * Get the client principal name from the decoded service ticket.
   * 
   * @return the client principal name
   */
  public String getClientPrincipalName() {
    if (!decoded) {
      decodeServiceTicket();
    }
    return cname;
  }
  
  /**
   * Get the session key from the decoded service ticket.
   * 
   * @return the session key
   */
  public EncryptionKey getSessionKey() {
    if (!decoded) {
      decodeServiceTicket();
    }
    return sessionKey;
  }
  
  // Decode the service ticket.
  private void decodeServiceTicket() {
    try {
      parseServiceTicket(serviceTicket);
      decoded = true;
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
  
  // Parses the service ticket (GSS AP-REQ token)
  private void parseServiceTicket(byte[] ticket) throws Exception {
    DerInputStream ticketStream = new DerInputStream(ticket);
    DerValue[] values = ticketStream.getSet(ticket.length, true);
    
    // Look for the AP_REQ.
    //
    // AP-REQ ::= [APPLICATION 14] SEQUENCE
    for (int i = 0; i < values.length; i++) {
      DerValue value = values[i];
      if (value.isConstructed((byte) 14)) {
        value.resetTag(DerValue.tag_Set);
        parseApReq(value.toDerInputStream(), value.length());
        return;
      }
    }
    throw new Exception("Could not find AP-REQ in service ticket.");
  }
  
  // Parse the GSS AP-REQ token.
  private void parseApReq(DerInputStream reqStream, int len) throws Exception {
    byte apOptions = 0;
    DerValue ticket = null;
    
    DerValue[] values = reqStream.getSet(len, true);
    
    //
    // AP-REQ ::= {
    // pvno[0] INTEGER,
    // msg-type[1] INTEGER,
    // ap-options[2] APOptions,
    // ticket[3] Ticket,
    // authenticator[4] EncryptedData
    // }
    //
    for (int i = 0; i < values.length; i++) {
      DerValue value = values[i];
      if (value.isContextSpecific((byte) 2)) {
        apOptions = value.getData().getDerValue().getBitString()[0];
        // apOptions not used yet.
      } else if (value.isContextSpecific((byte) 3)) {
        ticket = value.getData().getDerValue();
      }
    }
    
    if (ticket == null) {
      throw new Exception("No Ticket found in AP-REQ PDU");
    }
    decryptTicket(new Ticket(ticket), subject);
  }
  
  // Decrypt the ticket.
  // APOptions ::= BIT STRING {
  // reserved(0),
  // use-session-key(1),
  // mutual-required(2)
  // }
  // Ticket ::= [APPLICATION 1] SEQUENCE {
  // tkt-vno[0] INTEGER,
  // realm[1] Realm,
  // sname[2] PrincipalName,
  // enc-part[3] EncryptedData
  // }
  //
  // EncTicketPart ::= [APPLICATION 3] SEQUENCE {
  // flags[0] TicketFlags,
  // key[1] EncryptionKey,
  // crealm[2] Realm,
  // cname[3] PrincipalName,
  // transited[4] TransitedEncoding,
  // authtime[5] KerberosTime,
  // starttime[6] KerberosTime OPTIONAL,
  // endtime[7] KerberosTime,
  // renew-till[8] KerberosTime OPTIONAL,
  // caddr[9] HostAddresses OPTIONAL,
  // authorization-data[10] AuthorizationData OPTIONAL
  // }
  
  private void decryptTicket(Ticket ticket, Subject svrSub) throws Exception {
    System.out.println("key encryption type = " + ticket.encPart.getEType());
    // Get the private key that matches the encryption type of the ticket.
    EncryptionKey key = getPrivateKey(svrSub, ticket.encPart.getEType());
    // Decrypt the service ticket and get the cleartext bytes.
    byte[] ticketBytes = ticket.encPart.decrypt(key, KeyUsage.KU_TICKET);
    if (ticketBytes.length <= 0) {
      throw new Exception("Key is empty.");
    }
    // EncTicketPart provides access to the decrypted attributes of the service
    // ticket.
    byte[] temp = ticket.encPart.reset(ticketBytes, true);
    EncTicketPart encPart = new EncTicketPart(temp);
    this.sessionKey = encPart.key;
    this.cname = encPart.cname.toString();
  }
  
  // Get the private server key.
  private EncryptionKey getPrivateKey(Subject sub, int keyType) throws Exception {
    KerberosKey key = getKrbKey(sub, keyType);
    return new EncryptionKey(key.getEncoded(), key.getKeyType(), new Integer(keyType));
  }
  
  // Get the Kerberos Key from the subject that matches the given key type.
  private KerberosKey getKrbKey(Subject sub, int keyType) {
    for (KerberosKey key : sub.getPrivateCredentials(KerberosKey.class)) {
      System.out.println(key);
      if (key.getKeyType() == keyType) {
        return key;
      }
    }
    return null;
  }
  
}
