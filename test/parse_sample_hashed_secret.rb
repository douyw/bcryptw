require 'bcrypt'

    def split_hash(h)
      _, v, c, mash = h.split('$')
      return v.to_str, c.to_i, h[0, 29].to_str, mash[-31, 31].to_str
    end

secret = 'qwert12345'
hashed_secret = '$2a$10$qYZ0v5Cv3ZttLTUOe.2k5uKZN.Zcf4rkwb1tbhCKlUUuXP7cefU7q'
version, cost, salt, checksum = split_hash(hashed_secret)

puts hashed_secret
puts version, cost, salt, checksum

#puts ()
