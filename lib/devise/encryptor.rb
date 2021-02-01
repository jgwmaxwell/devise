# frozen_string_literal: true

require 'argon2'

module Devise
  module Encryptor
    def self.digest(klass, password)
      password = "#{password}#{klass.pepper}" if klass.pepper.present?
      ::Argon2::Password.create(password)
    end

    def self.compare(klass, hashed_password, password)
      return false if hashed_password.blank?

      if hashed_password.start_with?('$argon2')
        password = "#{password}#{klass.pepper}" if klass.pepper.present?
        ::Argon2::Password.verify_password(password, hashed_password)
      else
        super
      end
    end
  end
end
