require 'openssl'
require 'digest'
require 'benchmark'


def findPrime (bits)
	prime = 0
	counter = 0
	until prime % 4 == 3 do
		prime = OpenSSL::BN::generate_prime(bits/2)
		counter = counter + 1
	end
	puts "Anahtar değeri için yapılan deneme sayısı: #{counter}"
	return prime.to_i
end

def genKeys(bits)
	p = findPrime(bits)
	q = findPrime(bits)
	n = p*q

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

	puts "CRT'ye verilecek değerler;"
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

puts "işlem için dosya program ile aynı dizinde olmalıdır."
puts "Dosyanın adını girin, uzantısı ile birlikte"
data = File.read("#{gets.chomp}")

puts "SHA256 için 1, MD5 için 2 giriniz"
hash_choice = gets.chomp

if hash_choice == 1
	hash_value = (Digest::SHA256.hexdigest(data)).to_i(16)
elsif
	hash_value = (Digest::MD5.hexdigest(data)).to_i(16)
end

puts "Dosya imzalamak için 1, İmza doğrulamak için 2'ye basın"
choice = gets.chomp.to_i

if choice == 1

	puts "Anahtar değerleri için bit uzayını belirtin, tavsiye edilen değer 512'dir."
	bits = gets.chomp.to_i

	start = Time.now
	keys = genKeys(bits)
	key_generation_time = Time.now - start

	puts "Anahtar oluşturulması için geçen süre: #{key_generation_time}"
	

	p = keys[0]
	puts "p: #{p}"

	q = keys[1]
	puts "q: #{q}"

	n = keys[2]
	puts "n: #{n}"

	puts "Dosyanın hash değeri: #{hash_value}"

	cypher = encrypt(hash_value, n)

	puts "İmza değeri: #{cypher}"

else

	puts "İmzayı giriniz"
	cypher = gets.chomp.to_i
	puts "p değerini giriniz"
	p = gets.chomp.to_i
	puts "q değerini giriniz"
	q = gets.chomp.to_i

	start = Time.now
	crt_messages = decrypt(cypher, p, q)

	verified = false

	crt_messages.each do |message|

		puts "CRT Sonucu: #{message}"

		if message == hash_value
			puts "Dosya başarıyla doğrulandı"
			puts "Dosyanın hash değeri: #{message}"
			verified = true
		end

	end

	if verified == false
		puts "Dosya verilen değerler ile doğrulanamadı. Dosya bozulmuş ya da imza değerlerinde hata olabilir."
	end
	decrypt_time = Time.now - start
	puts "İmza doğrulamasında geçen süre: #{decrypt_time}"
end








