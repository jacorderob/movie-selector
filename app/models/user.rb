class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable,
         :omniauthable, omniauth_providers: %i[facebook google_oauth2]

  def self.from_omniauth(auth)
    puts "privider", auth.provider
    puts "uid", auth.uid
    puts "info", auth.info
    where(provider: auth.provider, uid: auth.uid).first_or_create do |user|
      puts "user", user.as_json
      user.email = auth.info.email
      user.password = Devise.friendly_token[0, 20]
      user.name = auth.info.name
      puts "user", user.as_json
    end
  end
end
