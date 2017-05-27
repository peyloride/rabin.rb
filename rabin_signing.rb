require 'openssl'
require 'digest'
require 'securerandom'
require 'prime'
require 'benchmark'

def findPrime (bits)
	prime = 0
	counter = 0
	until prime % 4 == 3 do
		prime = OpenSSL::BN::generate_prime(bits/2)
		counter = counter + 1
	end
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

if ARGV[0] == nil
	abort "Usage is ruby test2.rb [filename_with_extension] [SHA256 or MD5] "+
	"[sign or verify] [bit size if signing (recommended: 512)]"
end
file_name = ARGV[0]
if (ARGV[1] == 'SHA256')
	hash_choice = 1
else
	hash_choice = 0
end
if (ARGV[2] == 'sign')
	operation_choice = 1
else
	operation_choice = 0
end

bits = ARGV[3].to_i if ARGV[3] != nil


data = File.read(file_name)

if operation_choice == 1

	puts "File sign operation started.."

	keys = genKeys(bits)
	p = keys[0]
	q = keys[1]
	n = keys[2]

	padding_counter = 0
	hash_value = 0
	temp_data = ""
	random_padding = 0

	loop do
		random_padding = SecureRandom.hex(8).to_i(16)
		temp_data = data + random_padding.to_s

		if hash_choice == 1
			hash_value = (Digest::SHA256.hexdigest(temp_data)).to_i(16)
		else
			hash_value = (Digest::MD5.hexdigest(temp_data)).to_i(16)
		end

		padding_counter = padding_counter + 1

		condition1 = hash_value.to_bn.mod_exp(((p-1)/2), p) == 1
		condition2 = hash_value.to_bn.mod_exp(((q-1)/2), q) == 1
		break if(condition1 && condition2)
	end

	puts "Number of retries to find appropriate padding: #{padding_counter}"

	message_p1 = hash_value.to_bn.mod_exp(((p+1)/4), p)
	message_p2 = p - message_p1
	message_q1 = hash_value.to_bn.mod_exp(((q+1)/4), q)
	message_q2 = q - message_q1

	crt_values = []
	crt_values << chinese_remainder([p.to_i,q.to_i],[message_p1.to_i, message_q1.to_i])
	crt_values << chinese_remainder([p.to_i,q.to_i],[message_p1.to_i, message_q2.to_i])
	crt_values << chinese_remainder([p.to_i,q.to_i],[message_p2.to_i, message_q1.to_i])
	crt_values << chinese_remainder([p.to_i,q.to_i],[message_p2.to_i, message_q2.to_i])

	puts "hash value: #{hash_value}"
	puts "p: #{p}"
	puts "q: #{q}"
	puts "R: #{random_padding}"
	puts "Z: #{crt_values[0]}"
	puts "n: #{n}"

	File.open("signature.key", "w+") do |file|
		file.puts random_padding
		file.puts crt_values[0]
		file.puts n
	end
else
	puts "Verification started.."
	puts "Please make sure you have signature.key file within same folder."
	signature_keys = []

	File.readlines("signature.key").each do |line|
		signature_keys << line
	end

	random_padding_file = signature_keys[0].to_i
	z = signature_keys[1].to_i
	n = signature_keys[2].to_i

	data = data + random_padding_file.to_s

	if hash_choice == 1
		hash_value = (Digest::SHA256.hexdigest(data)).to_i(16)
	else
		hash_value = (Digest::MD5.hexdigest(data)).to_i(16)
	end

	start_time = Time.now
	recovered_sign = z.to_bn.mod_exp(2, n)

	puts "Elapsed Time: #{(Time.now - start_time)*1000} miliseconds"
	puts "Z value: #{z}"
	puts "publick key: #{n}"
	puts "Recovered sign: #{recovered_sign}"
	puts "hash value: #{hash_value}"

	if(hash_value == recovered_sign)
		puts "File verified successfully"
	else
		puts "File verification failed"
	end
end