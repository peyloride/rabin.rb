require 'openssl'
require 'digest'


def findPrime (bits)
	prime = 0
	until prime % 4 == 3 do
		prime = OpenSSL::BN::generate_prime(bits/2)
	end
	return prime
end

def genKeys(bits)
	p = findPrime(bits)
	q = findPrime(bits)
	n = p*q

	keys = [p,q,n]
end

def encrypt(message,n)
	message.to_i.to_bn.mod_exp(2, n).to_i
end

def extended_gcd(a, b)
  last_remainder, remainder = a.abs, b.abs
  x, last_x, y, last_y = 0, 1, 1, 0
  while remainder != 0
    last_remainder, (quotient, remainder) = remainder, last_remainder.divmod(remainder)
    x, last_x = last_x - quotient*x, x
    y, last_y = last_y - quotient*y, y
  end
  return last_remainder, last_x * (a < 0 ? -1 : 1)
end
 
def invmod(e, et)
  g, x = extended_gcd(e, et)
  if g != 1
    raise 'Multiplicative inverse modulo does not exist!'
  end
  x % et
end
 
def chinese_remainder(mods, remainders)
  max = mods.inject( :* )  # product of all moduli
  series = remainders.zip(mods).map{ |r,m| (r * max * invmod(max/m, m) / m) }
  series.inject( :+ ) % max 
end

def decrypt(cypher, p, q)
	n = p * q

	message_p1 = cypher.to_bn.mod_exp(((p+1)/4), p)
	message_p2 = p - message_p1
	message_q1 = cypher.to_bn.mod_exp(((q+1)/4), q)
	message_q2 = q - message_q1

  crt_messages = []
	crt_messages << chinese_remainder([p.to_i,q.to_i],[message_p1.to_i, message_q1.to_i])
	crt_messages << chinese_remainder([p.to_i,q.to_i],[message_p1.to_i, message_q2.to_i])
	crt_messages << chinese_remainder([p.to_i,q.to_i],[message_p2.to_i, message_q1.to_i])
	crt_messages << chinese_remainder([p.to_i,q.to_i],[message_p2.to_i, message_q2.to_i])
end

keys = genKeys(512);

p = keys[0]

q = keys[1]

n = keys[2]


string = (Digest::MD5.hexdigest "Hello!").to_i(16)

puts string

cypher = encrypt(string, n)

p "cypher #{cypher}"

crt_messages = decrypt(cypher, p, q)

crt_messages.each do |message|

  puts message

end

