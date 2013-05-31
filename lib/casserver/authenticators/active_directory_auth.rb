# -*- coding: utf-8 -*-

require 'casserver/authenticators/base'
require 'adauth'

# ------------------------------------------------------------
# 微软活动目录认证器
# ------------------------------------------------------------

class CASServer::Authenticators::ActiveDirectoryAuth < CASServer::Authenticators::Base

  # --- 认证 --------------------------------------------------
  def validate(credentials)
    read_standard_credentials(credentials)

    return false if @password.blank?

    raise CASServer::AuthenticatorError, "Cannot validate credentials because the authenticator hasn't yet been configured" unless @options
    raise CASServer::AuthenticatorError, "Invalid E-Mail authenticator configuration!" unless @options[:ad]
    raise CASServer::AuthenticatorError, "You must specify a Doamin, a Server and a Base in the ActiveDirectoryAuth configuration!" unless (@options[:ad][:domain] && @options[:ad][:server] && @options[:ad][:base])

    begin
      Adauth.configure do |c|
        c.domain = @options[:ad][:domain]
        c.server = @options[:ad][:server]
        c.base   = @options[:ad][:base]
      end

      auth = Adauth.authenticate(@username, @password)
      return not auth.nil?
    rescue => e
      raise CASServer::AuthenticatorError,
        "Active Directory authentication failed with '#{e}'. Check your authenticator configuration."
    end
  end
end
