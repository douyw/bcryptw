require 'bcrypt'
require 'digest'

plain="qwert12345"
salt = "eQ4JHcO8hXcZMrX2wcWHBa16"

password_md5 = Digest::MD5.digest(plain+salt)

#puts "password_md5; #{password_md5}"

my_password = BCrypt::Password.create(password_md5)
  #=> "$2a$10$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cGLcZEiGDMVr5yUP1KUOYTa"

$i=0
while $i<100 do
  if my_password.empty?
    puts "i = #{$i}"
  end
  my_password = BCrypt::Password.create(password_md5)
  $i += 1
end
puts my_password.empty?, $i

