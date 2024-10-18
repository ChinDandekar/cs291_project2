require 'json'

for invalid_body in ["", "{", "}", "hello", "{'a': 1}"]
  begin
    JSON.parse(invalid_body)
    puts 'ez money'
  rescue JSON::ParserError
    puts "ruh roh"
  end
end