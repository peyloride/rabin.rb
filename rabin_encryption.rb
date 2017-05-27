require 'openssl'
require 'digest'

def findPrime (bits)
	prime = 0
	counter = 0
	until prime % 4 == 3 do
		prime = OpenSSL::BN::generate_prime(bits/2)
		counter = counter + 1
	end
	puts "Number of retries to get big prime number: #{counter}"
	return prime.to_i
end

def genKeys(bits)
	p = findPrime(bits)
	q = findPrime(bits)
	n = p*q

	File.open("private.key", "w+") do |file|
		file.puts p
		file.puts q
	end

	keys = [p,q,n]
end

def encrypt(message,n)
	message.to_bn.mod_exp(2, n)
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

	puts "Values to be used in CRT;"
	puts "p1: #{message_p1}"
	puts "p2: #{message_p2}"
	puts "q1: #{message_q1}"
	puts "q2: #{message_q2}"

    crt_messages = []
	crt_messages << chinese_remainder([p.to_i,q.to_i],[message_p1.to_i, message_q1.to_i])
	crt_messages << chinese_remainder([p.to_i,q.to_i],[message_p1.to_i, message_q2.to_i])
	crt_messages << chinese_remainder([p.to_i,q.to_i],[message_p2.to_i, message_q1.to_i])
	crt_messages << chinese_remainder([p.to_i,q.to_i],[message_p2.to_i, message_q2.to_i])
end

puts "To process, program and file must be in same folder."
puts "Please give in Filename with the extension"
data = File.read("#{gets.chomp}")

puts "For SHA256 enter 1, for MD5 enter 2"
hash_choice = gets.chomp

if hash_choice == 1
	hash_value = (Digest::SHA256.hexdigest(data)).to_i(16)
elsif
	hash_value = (Digest::MD5.hexdigest(data)).to_i(16)
end

puts "Press 1 to sign a file or press 2 to verify file with signature.key and private.key file"
choice = gets.chomp.to_i

if choice == 1

	puts "This will create two files"
	puts "signature.key file which has signature of file"
	puts "private.key file which has private values such as p and q"
	puts "You can use these files to verify file after signing"
	puts "Prime numbers (p and q) length in bits? (Recommended 512)"
	bits = gets.chomp.to_i

	start = Time.now
	keys = genKeys(bits)
	key_generation_time = Time.now - start

	puts "Key generation time: #{key_generation_time}"

	p = keys[0]
	puts "p: #{p}"

	q = keys[1]
	puts "q: #{q}"

	n = keys[2]
	puts "n: #{n}"

	puts "Hash value of file: #{hash_value}"

	cypher = encrypt(hash_value, n)

	puts "Produced signature value for file: #{cypher}"

	File.open("signature.key", "w+") do |file|
		file.puts cypher
	end
else

	puts "File name of key file which has signature"
	cypher = File.read("#{gets.chomp}").to_i
	puts "File name of key file which has private keys such as p and q"
	private_key = gets.chomp
	keys = []

	File.readlines("#{private_key}").each do |line|
		keys << line
	end

	p = keys[0].to_i
	q = keys[1].to_i

	start = Time.now
	crt_messages = decrypt(cypher, p, q)

	verified = false

	crt_messages.each do |message|
		puts "CRT Results: #{message}"

		if message == hash_value
			puts "File verified successfully"
			puts "Hash value of the file: #{message}"
			verified = true
		end
	end

	if verified == false
		puts "File can not be verified with given values. File or key values may be corrupted."
	end
	decrypt_time = Time.now - start
	puts "Decryption time: #{decrypt_time}"
end