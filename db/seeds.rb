# This file should contain all the record creation needed to seed the database with its default values.
# The data can then be loaded with the rake db:seed (or created alongside the db with db:setup).
#
# Examples:
#
#   cities = City.create([{ name: 'Chicago' }, { name: 'Copenhagen' }])
#   Mayor.create(name: 'Emanuel', city: cities.first)


User.create!(
  first_name: "Stephen",
  last_name: "Ramon",
  address: "4024 Bryn Mawr",
  city: "Dallas",
  zip: "75225",
  email: "sgr2ak@virginia.edu",
  phone: "999-999-9999",
  year: "H.S. Grad",
  password: "password",
  password_confirmation: "password",
  admin: true,
  activated: true,
  activated_at: Time.zone.now)
