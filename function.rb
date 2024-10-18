# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html
  
  if event["path"] == "/auth/token"
    if event["httpMethod"] == "POST"
      return post_auth_token(event: event)
    else
      return response(body: '', status: 405)
    end
  end

  if event["path"] == "/"
    if event["httpMethod"] == "GET"
      return get_authorized(event: event)
    else
      return response(body: '', status: 405)
    end
  end

  return response(body: '', status: 404)
end

def find_value_case_insensitively(hash, key)
  downcased_key = key.downcase
  matching_key = hash.keys.find { |k| k.downcase == downcased_key }
  matching_key ? hash[matching_key] : nil
end

def get_authorized(event:)
  # Regex to match 'Bearer ' followed by a JWT
  authorization = find_value_case_insensitively(event["headers"], "authorization")

  if !authorization
    return response(body: '', status: 403)
  end

  words = authorization.split
  if words.length != 2 or words[0] != "Bearer"
    return response(body: '', status: 403)
  end

  begin
    decoded = JWT.decode(words[1], ENV["JWT_SECRET"], true, { algorithm: 'HS256' })
  rescue JWT::DecodeError => e
    return response(body: '', status: 401)
  rescue JWT::ExpiredSignature
    return response(body: '', status: 401)
  end

  return response(body: decoded[0]["data"], status: 200)
end


def post_auth_token(event:)
  body = event["body"]
  begin
    JSON.parse(body)
  rescue JSON::ParserError
    return response(body: '', status: 422)
  rescue TypeError
  end

  if find_value_case_insensitively(event["headers"], "content-type") != "application/json"
    return response(body: '', status: 415)
  end

   # Get the current time
   current_time = Time.now.to_i

   # Define the payload
   payload = {
     data: event["body"],  # Include the request body as the 'data' field
     exp: current_time + 5,  # Expiration time: 5 seconds after generation
     nbf: current_time + 2   # Not before time: 2 seconds after generation
   }

   # Generate the JWT token with HS256 algorithm
   jwt_token = JWT.encode(payload, ENV['JWT_SECRET'], 'HS256')
 
   # Return the JSON response
   return response(body: {token: jwt_token}, status: 201)
end

def response(body: nil, status: 200)
  ans = {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
  # puts(ans)
  return ans
end

if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  ENV['JWT_SECRET'] = 'NOTASECRET'

  # Call /token
  PP.pp main(context: {}, event: {
               'body' => '{"name": "bboe"}',
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/auth/token'
             })

  PP.pp main(context: {}, event: {
               'body' => '',
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/auth/token'
             })
  # Generate a token
  payload = {
    data: { user_id: 128 },
    exp: Time.now.to_i + 1,
    nbf: Time.now.to_i
  }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  # Call /
  PP.pp main(context: {}, event: {
               'headers' => { 'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json' },
               'httpMethod' => 'GET',
               'path' => '/'
             })
  PP.pp main(context: {}, event: {
              'headers' => { 'AuTHorization' => "Bearer #{token}",
                             'Content-Type' => 'application/json' },
              'httpMethod' => 'GET',
              'path' => '/'
            })
end
