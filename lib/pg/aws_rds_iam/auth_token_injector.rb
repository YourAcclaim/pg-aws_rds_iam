# frozen_string_literal: true

module PG
  module AWS_RDS_IAM
    class AuthTokenInjector
      def initialize(auth_token_generators: AWS_RDS_IAM.auth_token_generators)
        @auth_token_generators = auth_token_generators
        @connection_defaults = PG::Connection.conndefaults_hash
      end

      def inject_into_connection_string(connection_string)
        connection_info = ConnectionInfo.from_connection_string(connection_string)
        return connection_string unless generate_auth_token?(connection_info)

        auth_token = generate_auth_token(connection_info)

        if auth_token.respond_to?(:password)
          connection_info.password = auth_token.password
          connection_info.user = auth_token.user if auth_token.respond_to?(:user?) && auth_token.user?
        else
          connection_info.password = auth_token.to_s
        end

        connection_info.to_s
      end

      def inject_into_psql_env!(configuration_hash, psql_env)
        connection_info = ConnectionInfo.from_active_record_configuration_hash(configuration_hash)
        return unless generate_auth_token?(connection_info)

        auth_token = generate_auth_token(connection_info)
        if auth_token.respond_to?(:password)
          psql_env["PGPASSWORD"] = auth_token.password
          psql_env["PGUSER"] = auth_token.user if auth_token.respond_to?(:user) && auth_token.user?
        else
          psql_env["PGPASSWORD"] = auth_token.to_s
        end
      end

      private

      def generate_auth_token?(connection_info)
        connection_info.auth_token_generator_name
      end

      def generate_auth_token(connection_info)
        @auth_token_generators
          .fetch(connection_info.auth_token_generator_name)
          .call(
            user: connection_info.user || default(:user),
            host: connection_info.host || default(:host),
            port: connection_info.port || default(:port)
          )
      end

      def default(key)
        @connection_defaults.fetch(key)
      end
    end

    private_constant :AuthTokenInjector
  end
end
