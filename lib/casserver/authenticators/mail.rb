require 'casserver/authenticators/base'
require 'net/smtp'

# Basic Mail SMTP authenticator.
class CASServer::Authenticators::Mail < CASServer::Authenticators::Base
  def validate(credentials)
    read_standard_credentials(credentials)

    return false if @password.blank?

    raise CASServer::AuthenticatorError, "Cannot validate credentials because the authenticator hasn't yet been configured" unless @options
    raise CASServer::AuthenticatorError, "Invalid E-Mail authenticator configuration!" unless @options[:mail]
    raise CASServer::AuthenticatorError, "You must specify a smtp server host and domain in the E-Mail configuration!" unless @options[:mail][:domain] || @options[:mail][:server]

    raise CASServer::AuthenticatorError, "The username '#{@username}' contains invalid characters." if (@username =~ /[*\(\)\0\/]/)

    @mail = Net::SMTP.start(@options[:mail][:server], @options[:mail][:port] || 25)
    @options[:mail][:domain] ||= @options[:mail][:server]

    begin
      auth = @mail.authenticate(@username, @password, @options[:mail][:auth_type].to_sym)
      @mail.finish

      create_extra_attributes
      return auth.status == "235"
    rescue => e
      raise CASServer::AuthenticatorError,
        "E-Mail authentication failed with '#{e}'. Check your authenticator configuration."
    end
  end

  private
  def create_extra_attributes
    require 'mongo'
    connection = Mongo::Connection.new(@options[:mongo][:server], @options[:mongo][:port] || 27017, :safe => true)
    db = connection.db(@options[:mongo][:db])
    users = db[@options[:mongo][:doc]].find(:login => @username).to_a

    attrs = {}
    users.each do |user|
      @options[:extra_attributes].each do |k,field|
        attrs[k] = attrs[k] || []
        attrs[k] << user[field]
      end
    end

    @extra_attributes = attrs
  end

end
