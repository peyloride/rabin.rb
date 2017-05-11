require 'securerandom' #To provide better randomness 

puts "File name to corrupt with extension"
file_name = gets.chomp
file = File.read(file_name)
size = file.length

puts "File length: #{size}"

puts "Value of the corruption %ratio"
ratio = gets.chomp.to_i

corruption = size * ratio / 100
puts "Characters to be corrupted: #{corruption}"

indices = (0..size).to_a.shuffle #to make sure every indice is different from each other

for i in (1..corruption)
	temp = file[indices[i]]
	until file[indices[i]] != temp do #make sure that previous value is not the same with new value
		file[indices[i]] = SecureRandom.random_number(33..126).chr
	end
end

new_file = File.open(file_name, 'w') do |new_file|
	new_file << file
end
